package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"localscan/display"
	"localscan/scanner"
)

func main() {
	var (
		ifaceName string
		timeout   int
		workers   int
		format    string
		output    string
		diff      bool
	)

	flag.StringVar(&ifaceName, "interface", "", "Network interface to use (auto-detect if empty)")
	flag.IntVar(&timeout, "timeout", 500, "Connection timeout in milliseconds")
	flag.IntVar(&workers, "workers", 100, "Number of concurrent workers")
	flag.StringVar(&format, "format", "table", "Output format: table, json, csv")
	flag.StringVar(&output, "o", "", "Output file path (default: stdout)")
	flag.BoolVar(&diff, "diff", false, "Compare with previous scan results")
	flag.Parse()

	// Validate format
	switch format {
	case "table", "json", "csv":
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format %q (use table, json, or csv)\n", format)
		os.Exit(1)
	}

	// Detect network interface
	info, err := scanner.DetectInterface(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Calculate hosts to scan
	hosts := scanner.HostsInNetwork(info.Network)
	if len(hosts) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no hosts in network %s\n", info.CIDR())
		os.Exit(1)
	}

	cidr := info.CIDR()
	total := len(hosts)

	display.PrintHeader(cidr, total)

	// Start scan
	start := time.Now()
	progressCh := make(chan scanner.Progress, workers)

	var results []scanner.ScanResult
	done := make(chan struct{})

	// Run scan in background goroutine
	go func() {
		results = scanner.Scan(hosts, workers, time.Duration(timeout)*time.Millisecond, progressCh)
		close(progressCh)
		close(done)
	}()

	// Display progress from channel until closed
	maxProgress := 0
	for p := range progressCh {
		if p.Current > maxProgress {
			maxProgress = p.Current
		}
		if p.Found != nil {
			display.PrintFound(p.Found)
		}
		display.PrintProgress(maxProgress, total, p.IP)
	}

	<-done

	display.PrintComplete(total)

	// Enrich all results with hostname, MAC, vendor
	arpTable := scanner.GetARPTable()
	for i := range results {
		ipStr := results[i].IP.String()
		results[i].Hostname = scanner.ResolveHostname(ipStr)
		if mac, ok := arpTable[ipStr]; ok {
			results[i].MAC = mac
			results[i].Vendor = scanner.LookupVendor(mac)
		} else {
			results[i].MAC = "-"
			results[i].Vendor = "-"
		}
	}

	// Sort results by IP
	sort.Slice(results, func(i, j int) bool {
		return ipToUint32(results[i].IP) < ipToUint32(results[j].IP)
	})

	// Diff mode: compare with previous scan
	if diff {
		previous, err := scanner.LoadHistory()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Note: no previous scan data found, all hosts marked as NEW\n")
		}
		results = scanner.ComputeDiff(results, previous)
		// Re-sort after adding GONE entries
		sort.Slice(results, func(i, j int) bool {
			return ipToUint32(results[i].IP) < ipToUint32(results[j].IP)
		})
	}

	// Save current results for future diff (only non-GONE entries)
	if diff {
		var toSave []scanner.ScanResult
		for _, r := range results {
			if r.Status != "GONE" {
				toSave = append(toSave, r)
			}
		}
		if err := scanner.SaveHistory(toSave); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save scan history: %v\n", err)
		}
	}

	// Determine output writer
	var w io.Writer = os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	elapsed := time.Since(start).Round(100 * time.Millisecond).String()

	switch format {
	case "json":
		display.PrintResultsJSON(w, results, elapsed)
	case "csv":
		display.PrintResultsCSV(w, results, elapsed)
	default:
		display.PrintResults(w, results, elapsed)
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
