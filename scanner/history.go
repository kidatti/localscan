package scanner

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
)

// historyEntry is the JSON-serializable form of a scan result.
type historyEntry struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Method    string `json:"method"`
	OpenPorts []int  `json:"open_ports"`
}

func historyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".localscan", "last.json")
}

// SaveHistory writes the current scan results to ~/.localscan/last.json.
func SaveHistory(results []ScanResult) error {
	p := historyPath()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}

	entries := make([]historyEntry, len(results))
	for i, r := range results {
		ports := r.OpenPorts
		if ports == nil {
			ports = []int{}
		}
		entries[i] = historyEntry{
			IP:        r.IP.String(),
			Hostname:  r.Hostname,
			MAC:       r.MAC,
			Vendor:    r.Vendor,
			Method:    r.Method,
			OpenPorts: ports,
		}
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0644)
}

// LoadHistory reads the previous scan results from ~/.localscan/last.json.
func LoadHistory() ([]ScanResult, error) {
	data, err := os.ReadFile(historyPath())
	if err != nil {
		return nil, err
	}

	var entries []historyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	results := make([]ScanResult, len(entries))
	for i, e := range entries {
		results[i] = ScanResult{
			IP:        net.ParseIP(e.IP),
			Hostname:  e.Hostname,
			MAC:       e.MAC,
			Vendor:    e.Vendor,
			Method:    e.Method,
			OpenPorts: e.OpenPorts,
		}
	}
	return results, nil
}

// ComputeDiff compares current results with previous results and sets
// the Status field: "NEW" for hosts not in previous, "GONE" for hosts
// only in previous (appended to results with status "GONE").
// Hosts present in both get an empty Status (continuing).
func ComputeDiff(current, previous []ScanResult) []ScanResult {
	prevSet := make(map[string]bool)
	for _, r := range previous {
		prevSet[r.IP.String()] = true
	}

	curSet := make(map[string]bool)
	for i := range current {
		ip := current[i].IP.String()
		curSet[ip] = true
		if !prevSet[ip] {
			current[i].Status = "NEW"
		}
	}

	// Append GONE entries for hosts in previous but not in current
	for _, r := range previous {
		ip := r.IP.String()
		if !curSet[ip] {
			gone := r
			gone.Status = "GONE"
			current = append(current, gone)
		}
	}

	return current
}
