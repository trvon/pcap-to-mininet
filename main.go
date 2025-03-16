package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
	"github.com/trvon/pcap-to-mininet/pkg/pcapprocessor"
	"github.com/trvon/pcap-to-mininet/pkg/topology"
	"github.com/trvon/pcap-to-mininet/pkg/visualization"
)

func main() {
	pcapFile := flag.String("pcap", "", "PCAP file to analyze")
	pcapDir := flag.String("dir", "", "Directory containing PCAP files to analyze")
	outputFile := flag.String("output", "mininet_topology.py", "Output topology file")
	visualize := flag.Bool("visualize", true, "Generate visualization of the topology")
	visualizeFile := flag.String("viz-output", "", "Output file for visualization (default: derived from output file)")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	// Validate input flags
	if *pcapFile == "" && *pcapDir == "" {
		log.Fatal("Either --pcap or --dir must be specified")
	}

	// Set default visualization file if not specified
	vizOutputFile := *visualizeFile
	if *visualize && vizOutputFile == "" {
		baseFile := strings.TrimSuffix(*outputFile, filepath.Ext(*outputFile))
		vizOutputFile = baseFile + ".dot"
	}

	var allTrafficData []analyzer.Traffic

	if *pcapFile != "" {
		// Process single PCAP file
		if *verbose {
			log.Printf("Analyzing PCAP file: %s", *pcapFile)
		}

		trafficData, err := pcapprocessor.ParsePCAP(*pcapFile)
		if err != nil {
			log.Fatal(err)
		}

		allTrafficData = append(allTrafficData, trafficData...)

		if *verbose {
			log.Printf("Parsed %d packets from %s", len(trafficData), *pcapFile)
		}
	} else if *pcapDir != "" {
		// Process directory of PCAP files
		if *verbose {
			log.Printf("Analyzing all PCAP files in directory: %s", *pcapDir)
		}

		files, err := os.ReadDir(*pcapDir)
		if err != nil {
			log.Fatalf("Failed to read directory %s: %v", *pcapDir, err)
		}

		var pcapCount int
		for _, file := range files {
			if file.IsDir() {
				continue
			}

			// Check if the file has a pcap extension
			fileName := file.Name()
			if !strings.HasSuffix(strings.ToLower(fileName), ".pcap") &&
				!strings.HasSuffix(strings.ToLower(fileName), ".pcapng") {
				continue
			}

			fullPath := filepath.Join(*pcapDir, fileName)
			if *verbose {
				log.Printf("Processing PCAP file: %s", fullPath)
			}

			trafficData, err := pcapprocessor.ParsePCAP(fullPath)
			if err != nil {
				log.Printf("Warning: Failed to parse %s: %v", fullPath, err)
				continue
			}

			allTrafficData = append(allTrafficData, trafficData...)
			pcapCount++

			if *verbose {
				log.Printf("Parsed %d packets from %s", len(trafficData), fileName)
			}
		}

		if pcapCount == 0 {
			log.Fatal("No valid PCAP files found in the specified directory")
		}

		if *verbose {
			log.Printf("Processed %d PCAP files with a total of %d packets",
				pcapCount, len(allTrafficData))
		}
	}

	// Identify local networks and subnets
	subnets := topology.IdentifySubnets(allTrafficData)
	if *verbose {
		log.Printf("Identified %d subnets", len(subnets))
		for subnet, count := range subnets {
			log.Printf("  Subnet %s: %d hosts", subnet, count)
		}
	}

	networkTopology := topology.InferTopology(allTrafficData)
	refinedTopology := analyzer.ApplyFuzzyLogic(networkTopology)

	if *verbose {
		log.Printf("Network topology inferred with %d nodes", len(refinedTopology.Nodes))
		printTopologySummary(refinedTopology)
	}

	err := visualization.GenerateMininetTopology(refinedTopology, *outputFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Mininet topology generated successfully to %s\n", *outputFile)

	// Generate visualization if requested
	if *visualize {
		err := visualization.GenerateTopologyVisualization(refinedTopology, vizOutputFile)
		if err != nil {
			log.Printf("Warning: Failed to generate visualization: %v", err)
		} else {
			fmt.Printf("Topology visualization generated to %s\n", vizOutputFile)
			fmt.Printf("To generate a PNG image, run: dot -Tpng %s -o %s.png\n",
				vizOutputFile, strings.TrimSuffix(vizOutputFile, filepath.Ext(vizOutputFile)))
		}
	}
}

// Print a summary of the inferred topology
func printTopologySummary(topology analyzer.NetworkTopology) {
	// Count node types
	var clients, servers, routers, switches, gateways, dnsServers int
	for _, node := range topology.Nodes {
		switch node.Role {
		case "client":
			clients++
		case "server":
			servers++
		case "router":
			routers++
		case "switch":
			switches++
		case "gateway":
			gateways++
		case "dns-server":
			dnsServers++
		}
	}

	log.Printf("Network nodes by role:")
	log.Printf("  Clients: %d", clients)
	log.Printf("  Servers: %d", servers)
	log.Printf("  DNS Servers: %d", dnsServers)
	log.Printf("  Routers: %d", routers)
	log.Printf("  Switches: %d", switches)
	log.Printf("  Gateways: %d", gateways)

	// List identified subnets
	var subnets = make(map[string]int)
	for _, node := range topology.Nodes {
		if node.Subnet != "" {
			subnets[node.Subnet]++
		}
	}

	log.Printf("Subnets detected:")
	for subnet, count := range subnets {
		log.Printf("  %s: %d hosts", subnet, count)
	}

	// Print MAC-to-role mapping for gateways and routers
	log.Printf("MAC-based device role detection:")
	var gatewayMACs, routerMACs, hostMACs int
	for _, role := range topology.MACRoles {
		switch role {
		case "gateway":
			gatewayMACs++
		case "multi-homed":
			routerMACs++
		case "host":
			hostMACs++
		}
	}

	log.Printf("  Gateway MACs: %d", gatewayMACs)
	log.Printf("  Router/Multi-homed MACs: %d", routerMACs)
	log.Printf("  Host MACs: %d", hostMACs)

	// Print detailed information about gateways
	log.Printf("Gateway details:")
	for ip, node := range topology.Nodes {
		if node.Role == "gateway" {
			macRole := "unknown"
			if node.MAC != "" {
				if role, exists := topology.MACRoles[node.MAC]; exists {
					macRole = role
				}
			}
			log.Printf("  IP: %s, MAC: %s, MAC-based role: %s, Confidence: %.2f",
				ip, node.MAC, macRole, node.Confidence)
		}
	}
}