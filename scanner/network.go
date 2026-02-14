package scanner

import (
	"fmt"
	"net"
)

// InterfaceInfo holds network interface details.
type InterfaceInfo struct {
	Name    string
	IP      net.IP
	Network *net.IPNet
}

// DetectInterface finds an active non-loopback IPv4 interface.
// If ifaceName is non-empty, it looks for that specific interface.
func DetectInterface(ifaceName string) (*InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if ifaceName != "" && iface.Name != ifaceName {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			return &InterfaceInfo{
				Name:    iface.Name,
				IP:      ip4,
				Network: ipNet,
			}, nil
		}
	}

	if ifaceName != "" {
		return nil, fmt.Errorf("interface %q not found or has no IPv4 address", ifaceName)
	}
	return nil, fmt.Errorf("no active network interface found")
}

// HostsInNetwork returns all usable host IPs in the given network (excluding network and broadcast addresses).
func HostsInNetwork(network *net.IPNet) []net.IP {
	var hosts []net.IP
	ip := network.IP.Mask(network.Mask)

	// Calculate the number of bits in the mask
	ones, bits := network.Mask.Size()
	if ones == 0 || ones == bits {
		return nil
	}

	// Iterate all IPs in range
	for current := cloneIP(ip); network.Contains(current); incIP(current) {
		hosts = append(hosts, cloneIP(current))
	}

	// Remove network address (first) and broadcast address (last)
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	} else {
		hosts = nil
	}

	return hosts
}

// CIDR returns the CIDR notation string for the network.
func (info *InterfaceInfo) CIDR() string {
	ones, _ := info.Network.Mask.Size()
	networkIP := info.Network.IP.Mask(info.Network.Mask)
	return fmt.Sprintf("%s/%d", networkIP.To4(), ones)
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
