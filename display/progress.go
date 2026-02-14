package display

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"localscan/scanner"
)

const barWidth = 40

// PrintHeader prints the scan start message.
func PrintHeader(cidr string, total int) {
	fmt.Fprintf(os.Stderr, "Scanning %s (%d hosts)...\n", cidr, total)
}

// PrintProgress updates the progress bar on stderr.
func PrintProgress(current, total int, ip string) {
	pct := float64(current) / float64(total)
	filled := int(pct * barWidth)
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d scanning %s...   ", bar, current, total, ip)
}

// PrintFound prints a discovery message on stderr.
func PrintFound(result *scanner.ScanResult) {
	fmt.Fprintf(os.Stderr, "\r\033[K[+] Found: %s [%s]\n", result.IP, result.Method)
}

// PrintComplete clears the progress line and prints completion.
func PrintComplete(total int) {
	bar := strings.Repeat("=", barWidth)
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d Complete\n\n", bar, total, total)
}

// formatPorts returns a comma-separated string of port numbers.
func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "-"
	}
	sorted := make([]int, len(ports))
	copy(sorted, ports)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, p := range sorted {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// PrintResults prints the final results table to the given writer.
func PrintResults(w io.Writer, results []scanner.ScanResult, elapsed string) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No devices found.")
		return
	}

	// Calculate column widths
	maxIP, maxHost, maxMAC, maxVendor, maxMethod, maxPorts, maxStatus := 10, 8, 11, 6, 6, 5, 6
	for _, r := range results {
		if len(r.IP.String()) > maxIP {
			maxIP = len(r.IP.String())
		}
		if len(r.Hostname) > maxHost {
			maxHost = len(r.Hostname)
		}
		if len(r.MAC) > maxMAC {
			maxMAC = len(r.MAC)
		}
		if len(r.Vendor) > maxVendor {
			maxVendor = len(r.Vendor)
		}
		if len(r.Method) > maxMethod {
			maxMethod = len(r.Method)
		}
		portsStr := formatPorts(r.OpenPorts)
		if len(portsStr) > maxPorts {
			maxPorts = len(portsStr)
		}
		if len(r.Status) > maxStatus {
			maxStatus = len(r.Status)
		}
	}

	// Check if any result has a diff status
	hasDiff := false
	for _, r := range results {
		if r.Status != "" {
			hasDiff = true
			break
		}
	}

	// Build format string
	numW := len(fmt.Sprintf("%d", len(results)))
	if numW < 1 {
		numW = 1
	}

	if hasDiff {
		sep := fmt.Sprintf("+-%s-+-%s-+-%s-+-%s-+-%s-+-%s-+-%s-+-%s-+",
			strings.Repeat("-", numW+2),
			strings.Repeat("-", maxIP),
			strings.Repeat("-", maxHost),
			strings.Repeat("-", maxMAC),
			strings.Repeat("-", maxVendor),
			strings.Repeat("-", maxMethod),
			strings.Repeat("-", maxPorts),
			strings.Repeat("-", maxStatus),
		)

		header := fmt.Sprintf("| %s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |",
			padCenter("#", numW+2),
			maxIP, "IP Address",
			maxHost, "Hostname",
			maxMAC, "MAC Address",
			maxVendor, "Vendor",
			maxMethod, "Method",
			maxPorts, "Ports",
			maxStatus, "Status",
		)

		fmt.Fprintln(w, sep)
		fmt.Fprintln(w, header)
		fmt.Fprintln(w, sep)

		for i, r := range results {
			fmt.Fprintf(w, "| %*d   | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |\n",
				numW, i+1,
				maxIP, r.IP.String(),
				maxHost, r.Hostname,
				maxMAC, r.MAC,
				maxVendor, r.Vendor,
				maxMethod, r.Method,
				maxPorts, formatPorts(r.OpenPorts),
				maxStatus, r.Status,
			)
		}

		fmt.Fprintln(w, sep)
	} else {
		sep := fmt.Sprintf("+-%s-+-%s-+-%s-+-%s-+-%s-+-%s-+-%s-+",
			strings.Repeat("-", numW+2),
			strings.Repeat("-", maxIP),
			strings.Repeat("-", maxHost),
			strings.Repeat("-", maxMAC),
			strings.Repeat("-", maxVendor),
			strings.Repeat("-", maxMethod),
			strings.Repeat("-", maxPorts),
		)

		header := fmt.Sprintf("| %s | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |",
			padCenter("#", numW+2),
			maxIP, "IP Address",
			maxHost, "Hostname",
			maxMAC, "MAC Address",
			maxVendor, "Vendor",
			maxMethod, "Method",
			maxPorts, "Ports",
		)

		fmt.Fprintln(w, sep)
		fmt.Fprintln(w, header)
		fmt.Fprintln(w, sep)

		for i, r := range results {
			fmt.Fprintf(w, "| %*d   | %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |\n",
				numW, i+1,
				maxIP, r.IP.String(),
				maxHost, r.Hostname,
				maxMAC, r.MAC,
				maxVendor, r.Vendor,
				maxMethod, r.Method,
				maxPorts, formatPorts(r.OpenPorts),
			)
		}

		fmt.Fprintln(w, sep)
	}

	fmt.Fprintf(w, "Found %d devices in %s\n", len(results), elapsed)
}

// jsonResult is the JSON representation of a scan result.
type jsonResult struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Method    string `json:"method"`
	OpenPorts []int  `json:"open_ports"`
	Status    string `json:"status,omitempty"`
}

// PrintResultsJSON writes scan results as JSON.
func PrintResultsJSON(w io.Writer, results []scanner.ScanResult, elapsed string) {
	out := make([]jsonResult, len(results))
	for i, r := range results {
		ports := r.OpenPorts
		if ports == nil {
			ports = []int{}
		}
		out[i] = jsonResult{
			IP:        r.IP.String(),
			Hostname:  r.Hostname,
			MAC:       r.MAC,
			Vendor:    r.Vendor,
			Method:    r.Method,
			OpenPorts: ports,
			Status:    r.Status,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// PrintResultsCSV writes scan results as CSV.
func PrintResultsCSV(w io.Writer, results []scanner.ScanResult, elapsed string) {
	cw := csv.NewWriter(w)

	// Check if diff mode
	hasDiff := false
	for _, r := range results {
		if r.Status != "" {
			hasDiff = true
			break
		}
	}

	if hasDiff {
		cw.Write([]string{"IP", "Hostname", "MAC", "Vendor", "Method", "OpenPorts", "Status"})
	} else {
		cw.Write([]string{"IP", "Hostname", "MAC", "Vendor", "Method", "OpenPorts"})
	}

	for _, r := range results {
		row := []string{
			r.IP.String(),
			r.Hostname,
			r.MAC,
			r.Vendor,
			r.Method,
			formatPorts(r.OpenPorts),
		}
		if hasDiff {
			row = append(row, r.Status)
		}
		cw.Write(row)
	}
	cw.Flush()
}

func padCenter(s string, width int) string {
	if len(s) >= width {
		return s
	}
	left := (width - len(s)) / 2
	right := width - len(s) - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
