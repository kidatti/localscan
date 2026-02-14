package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ScanResult holds information about a discovered host.
type ScanResult struct {
	IP        net.IP
	Hostname  string
	MAC       string
	Vendor    string
	Method    string // Detection method: ICMP, TCP, UDP, ARP
	OpenPorts []int  // TCP ports that are open (accepted connection)
	Status    string // Diff status: "NEW", "GONE", or "" (continuing)
}

// Progress reports scan progress via a channel.
type Progress struct {
	Current int
	Total   int
	IP      string
	Found   *ScanResult // non-nil when a host is discovered
}

// TCP ports to probe — covers common services, IoT, and media devices.
var tcpPorts = []int{
	22, 23, 53, 80, 443, 445, 139, 548,       // SSH, Telnet, DNS, HTTP(S), SMB, AFP
	3389, 5900,                                 // RDP, VNC
	8080, 8443, 8008, 8009,                     // HTTP alt, Chromecast
	5353,                                       // mDNS (TCP)
	7000, 7100,                                 // AirPlay
	9100,                                       // Printer (RAW)
	62078,                                      // Apple iDevice
	1883, 8883,                                 // MQTT
	554,                                        // RTSP (cameras)
	5000, 5001,                                 // Synology, UPnP
	9090, 3000,                                 // Prometheus, Grafana, dev servers
}

// UDP ports for discovery probes.
var udpPorts = []int{
	5353,  // mDNS
	1900,  // SSDP (UPnP)
	137,   // NetBIOS
	161,   // SNMP
	53,    // DNS
	123,   // NTP
}

// Scan performs a multi-method scan on all hosts:
// 1. ICMP ping (system command)
// 2. TCP connect probe
// 3. UDP probe
// Then checks ARP table for additional hosts that responded at L2 but not L3+.
func Scan(hosts []net.IP, workers int, timeout time.Duration, progressCh chan<- Progress) []ScanResult {
	var (
		mu       sync.Mutex
		foundSet = make(map[string]bool)
		results  []ScanResult
		wg       sync.WaitGroup
		progress int64
	)

	jobs := make(chan int, len(hosts))
	total := len(hosts)

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				ip := hosts[idx]
				ipStr := ip.String()

				method, openPorts := detectHost(ipStr, timeout)

				cur := int(atomic.AddInt64(&progress, 1))
				p := Progress{
					Current: cur,
					Total:   total,
					IP:      ipStr,
				}

				if method != "" {
					mu.Lock()
					if !foundSet[ipStr] {
						foundSet[ipStr] = true
						result := ScanResult{IP: cloneIP(ip), Method: method, OpenPorts: openPorts}
						results = append(results, result)
						p.Found = &result
					}
					mu.Unlock()
				}

				progressCh <- p
			}
		}()
	}

	// Send jobs
	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// Phase 2: Check ARP table for hosts that responded to ARP but not to probes.
	// Our probe attempts triggered ARP resolution, so the OS ARP cache now
	// contains entries even for hosts that didn't respond to TCP/UDP/ICMP.
	arpTable := GetARPTable()
	for _, ip := range hosts {
		ipStr := ip.String()
		if foundSet[ipStr] {
			continue
		}
		if mac, ok := arpTable[ipStr]; ok && mac != "" {
			result := ScanResult{IP: cloneIP(ip), Method: "ARP"}
			results = append(results, result)
			progressCh <- Progress{
				Current: total,
				Total:   total,
				IP:      ipStr,
				Found:   &result,
			}
		}
	}

	return results
}

// detectHost tries each probe method in order and returns the name of
// the first method that detected the host (or "" if none succeeded),
// along with a list of open TCP ports.
func detectHost(ip string, timeout time.Duration) (string, []int) {
	icmpAlive := icmpPing(ip, timeout)
	tcpAlive, openPorts := tcpProbe(ip, timeout)

	if icmpAlive {
		return "ICMP", openPorts
	}
	if tcpAlive {
		return "TCP", openPorts
	}
	if udpProbe(ip, timeout) {
		return "UDP", openPorts
	}
	return "", nil
}

// icmpPing uses the system ping command (no root required on macOS/Linux).
func icmpPing(ip string, timeout time.Duration) bool {
	timeoutSec := int(timeout.Milliseconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutSec), ip)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), ip)
	default: // linux
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", max(1, timeoutSec/1000)), ip)
	}

	err := cmd.Run()
	return err == nil
}

// tcpProbe tries to connect to common ports on the given IP.
// Returns true if any port responds (open or refused = host alive),
// and a list of ports that accepted connections (open).
func tcpProbe(ip string, timeout time.Duration) (bool, []int) {
	alive := false
	var openPorts []int
	for _, port := range tcpPorts {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			alive = true
			openPorts = append(openPorts, port)
			continue
		}
		if isConnRefused(err) {
			alive = true
		}
	}
	return alive, openPorts
}

// udpProbe sends UDP packets to common discovery ports.
// A response or ICMP port-unreachable (which won't error on some OSes)
// indicates the host is alive.
func udpProbe(ip string, timeout time.Duration) bool {
	for _, port := range udpPorts {
		if udpCheck(ip, port, timeout) {
			return true
		}
	}
	return false
}

func udpCheck(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send a probe packet appropriate for the port
	var payload []byte
	switch port {
	case 5353: // mDNS query for _services._dns-sd._udp.local
		payload = mDNSQuery()
	case 1900: // SSDP M-SEARCH
		payload = ssdpSearch()
	case 137: // NetBIOS name query
		payload = netbiosQuery()
	case 161: // SNMP get-request (community: public)
		payload = snmpGetRequest()
	default:
		payload = []byte("\x00")
	}

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(payload)
	if err != nil {
		return false
	}

	buf := make([]byte, 512)
	conn.SetDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

// mDNSQuery returns a minimal mDNS query packet.
func mDNSQuery() []byte {
	return []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Query: _services._dns-sd._udp.local, type PTR, class IN
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,       // end of name
		0x00, 0x0C, // type PTR
		0x00, 0x01, // class IN
	}
}

// ssdpSearch returns an SSDP M-SEARCH packet.
func ssdpSearch() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n")
}

// netbiosQuery returns a NetBIOS name query packet.
func netbiosQuery() []byte {
	return []byte{
		0x80, 0x01, // Transaction ID
		0x00, 0x10, // Flags: broadcast
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Query: * (wildcard)
		0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x00,
		0x00, 0x21, // type NBSTAT
		0x00, 0x01, // class IN
	}
}

// snmpGetRequest returns a minimal SNMPv1 get-request (community: public).
func snmpGetRequest() []byte {
	return []byte{
		0x30, 0x26,
		0x02, 0x01, 0x00, // version: SNMPv1
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community: public
		0xa0, 0x19, // GetRequest PDU
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
		0x02, 0x01, 0x00, // error-status
		0x02, 0x01, 0x00, // error-index
		0x30, 0x0b, // varbind list
		0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1 (system)
		0x05, 0x00, // value: null
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
