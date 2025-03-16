package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Traffic represents a network traffic entry with enhanced metadata
type Traffic struct {
	SrcMAC       string
	DstMAC       string
	SrcIP        string
	DstIP        string
	Protocol     string
	SrcPort      uint16
	DstPort      uint16
	Timestamp    time.Time
	PacketSize   int
	FlowDuration time.Duration
	IsDNS        bool
	DNSQuery     string
}

// NetworkNode represents a node in the network with additional properties
type NetworkNode struct {
	IP               string
	MAC              string
	Subnet           string
	IsLocal          bool           // Whether this node is part of the local network
	Role             string         // "client", "server", "switch", "router", "gateway", "dns-server"
	Confidence       float64        // Fuzzy confidence score
	Connections      int            // Number of unique connections
	TotalTraffic     int64          // Total bytes transferred
	Services         map[uint16]int // Common ports used (for server identification)
	IsDNSServer      bool           // Whether this node acts as a DNS server
	DNSQueryCount    int            // Number of DNS queries handled
	DNSResponseCount int            // Number of DNS responses sent
}

// NetworkTopology represents the inferred network topology
type NetworkTopology struct {
	Nodes    map[string]*NetworkNode
	Edges    map[string]map[string]float64 // Source -> Destination -> Connection strength
	MACRoles map[string]string             // MAC address -> Role mapping from MAC-IP analysis
}

// FlowStats keeps track of flow statistics between node pairs
type FlowStats struct {
	PacketCount int
	ByteCount   int64
	FirstSeen   time.Time
	LastSeen    time.Time
	Ports       map[uint16]int
	Protocols   map[string]int
}

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

	var allTrafficData []Traffic

	if *pcapFile != "" {
		// Process single PCAP file
		if *verbose {
			log.Printf("Analyzing PCAP file: %s", *pcapFile)
		}

		trafficData, err := parsePCAP(*pcapFile)
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

			trafficData, err := parsePCAP(fullPath)
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
	subnets := identifySubnets(allTrafficData)
	if *verbose {
		log.Printf("Identified %d subnets", len(subnets))
		for subnet, count := range subnets {
			log.Printf("  Subnet %s: %d hosts", subnet, count)
		}
	}

	topology := inferTopology(allTrafficData)
	refinedTopology := applyFuzzyLogic(topology)

	if *verbose {
		log.Printf("Network topology inferred with %d nodes", len(refinedTopology.Nodes))
		printTopologySummary(refinedTopology)
	}

	err := generateMininetTopology(refinedTopology, *outputFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Mininet topology generated successfully to %s\n", *outputFile)

	// Generate visualization if requested
	if *visualize {
		err := generateTopologyVisualization(refinedTopology, vizOutputFile)
		if err != nil {
			log.Printf("Warning: Failed to generate visualization: %v", err)
		} else {
			fmt.Printf("Topology visualization generated to %s\n", vizOutputFile)
			fmt.Printf("To generate a PNG image, run: dot -Tpng %s -o %s.png\n",
				vizOutputFile, strings.TrimSuffix(vizOutputFile, filepath.Ext(vizOutputFile)))
		}
	}
}

func parsePCAP(filename string) ([]Traffic, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var traffic []Traffic
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		t := Traffic{
			Timestamp:  packet.Metadata().Timestamp,
			PacketSize: len(packet.Data()),
		}

		// Extract Ethernet (MAC) layer information
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			t.SrcMAC = eth.SrcMAC.String()
			t.DstMAC = eth.DstMAC.String()
		}

		// Extract IP layer information
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			t.SrcIP = ip.SrcIP.String()
			t.DstIP = ip.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			// Also handle IPv6
			ip, _ := ipv6Layer.(*layers.IPv6)
			t.SrcIP = ip.SrcIP.String()
			t.DstIP = ip.DstIP.String()
		}

		// Skip packets without IP information
		if t.SrcIP == "" || t.DstIP == "" {
			continue
		}

		// Extract TCP/UDP layer information
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			t.Protocol = "TCP"
			t.SrcPort = uint16(tcp.SrcPort)
			t.DstPort = uint16(tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			t.Protocol = "UDP"
			t.SrcPort = uint16(udp.SrcPort)
			t.DstPort = uint16(udp.DstPort)

			// Check for DNS (typically UDP port 53)
			if t.DstPort == 53 || t.SrcPort == 53 {
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					t.IsDNS = true

					// Extract query information if available
					if len(dns.Questions) > 0 {
						t.DNSQuery = string(dns.Questions[0].Name)
					}
				}
			}
		} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			t.Protocol = "ICMP"
		} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			t.Protocol = "ARP"
		}

		traffic = append(traffic, t)
	}

	return traffic, nil
}

// identifySubnets analyzes traffic data to identify subnets
func identifySubnets(trafficData []Traffic) map[string]int {
	subnets := make(map[string]int)
	ipToSubnet := make(map[string]string)

	// First, collect all unique IP addresses
	for _, t := range trafficData {
		srcIP := net.ParseIP(t.SrcIP)
		dstIP := net.ParseIP(t.DstIP)

		if srcIP != nil && !srcIP.IsLoopback() && !srcIP.IsMulticast() {
			// Calculate potential subnet for /24, /16, and /8
			ipStr := srcIP.String()
			parts := strings.Split(ipStr, ".")

			if len(parts) == 4 { // IPv4
				// Try different subnet masks
				for _, mask := range []int{24, 16} {
					var subnet string
					if mask == 24 {
						subnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
					} else if mask == 16 {
						subnet = fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])
					}

					subnets[subnet]++
					ipToSubnet[ipStr] = subnet
				}
			}
		}

		if dstIP != nil && !dstIP.IsLoopback() && !dstIP.IsMulticast() {
			// Similar logic for destination IPs
			ipStr := dstIP.String()
			parts := strings.Split(ipStr, ".")

			if len(parts) == 4 { // IPv4
				for _, mask := range []int{24, 16} {
					var subnet string
					if mask == 24 {
						subnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
					} else if mask == 16 {
						subnet = fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])
					}

					subnets[subnet]++
					ipToSubnet[ipStr] = subnet
				}
			}
		}
	}

	// Find the most common subnet
	var maxCount int
	for subnet, count := range subnets {
		if count > maxCount {
			maxCount = count
			// Store most common subnet in case we want to use it later
			_ = subnet // Currently unused but might be useful in future
		}
	}

	// Return only the significant subnets (filtering out noise)
	significantSubnets := make(map[string]int)
	threshold := maxCount / 10 // Require at least 10% of the most common subnet's count
	if threshold < 3 {
		threshold = 3 // Minimum threshold
	}

	for subnet, count := range subnets {
		if count >= threshold {
			significantSubnets[subnet] = count
		}
	}

	return significantSubnets
}

func inferTopology(trafficData []Traffic) NetworkTopology {
	topology := NetworkTopology{
		Nodes:    make(map[string]*NetworkNode),
		Edges:    make(map[string]map[string]float64),
		MACRoles: make(map[string]string),
	}

	// Get subnet information
	subnets := identifySubnets(trafficData)

	// Create IP to MAC mapping and analyze MAC to IP relationships for gateway detection
	ipToMAC := make(map[string]string)
	macToIPs := make(map[string]map[string]bool)

	for _, t := range trafficData {
		if t.SrcMAC != "" && t.SrcIP != "" {
			ipToMAC[t.SrcIP] = t.SrcMAC

			// Track all IPs associated with this MAC
			if _, exists := macToIPs[t.SrcMAC]; !exists {
				macToIPs[t.SrcMAC] = make(map[string]bool)
			}
			macToIPs[t.SrcMAC][t.SrcIP] = true
		}
		if t.DstMAC != "" && t.DstIP != "" {
			ipToMAC[t.DstIP] = t.DstMAC

			// Track all IPs associated with this MAC
			if _, exists := macToIPs[t.DstMAC]; !exists {
				macToIPs[t.DstMAC] = make(map[string]bool)
			}
			macToIPs[t.DstMAC][t.DstIP] = true
		}
	}

	// Identify potential gateways based on MAC to IP mapping
	topology.MACRoles = analyzeMACRoles(macToIPs)

	// Track flow statistics
	flows := make(map[string]map[string]*FlowStats)

	// First pass: Collect flow statistics
	for _, t := range trafficData {
		// Initialize node if not exists
		if _, exists := topology.Nodes[t.SrcIP]; !exists {
			// Determine subnet for this IP
			srcIP := net.ParseIP(t.SrcIP)
			subnet := ""
			isLocal := false

			if srcIP != nil {
				parts := strings.Split(t.SrcIP, ".")
				if len(parts) == 4 { // IPv4
					subnet24 := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
					if _, exists := subnets[subnet24]; exists {
						subnet = subnet24
						isLocal = true
					} else {
						subnet16 := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])
						if _, exists := subnets[subnet16]; exists {
							subnet = subnet16
							isLocal = true
						}
					}

					// Also check if IP is private
					if !isLocal {
						isLocal = isPrivateIP(srcIP)
					}
				}
			}

			topology.Nodes[t.SrcIP] = &NetworkNode{
				IP:               t.SrcIP,
				MAC:              ipToMAC[t.SrcIP],
				Subnet:           subnet,
				IsLocal:          isLocal,
				Confidence:       0.0,
				Services:         make(map[uint16]int),
				IsDNSServer:      false,
				DNSQueryCount:    0,
				DNSResponseCount: 0,
			}
		}

		if _, exists := topology.Nodes[t.DstIP]; !exists {
			// Similar logic for destination node
			dstIP := net.ParseIP(t.DstIP)
			subnet := ""
			isLocal := false

			if dstIP != nil {
				parts := strings.Split(t.DstIP, ".")
				if len(parts) == 4 { // IPv4
					subnet24 := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
					if _, exists := subnets[subnet24]; exists {
						subnet = subnet24
						isLocal = true
					} else {
						subnet16 := fmt.Sprintf("%s.%s.0.0/16", parts[0], parts[1])
						if _, exists := subnets[subnet16]; exists {
							subnet = subnet16
							isLocal = true
						}
					}

					// Also check if IP is private
					if !isLocal {
						isLocal = isPrivateIP(dstIP)
					}
				}
			}

			topology.Nodes[t.DstIP] = &NetworkNode{
				IP:               t.DstIP,
				MAC:              ipToMAC[t.DstIP],
				Subnet:           subnet,
				IsLocal:          isLocal,
				Confidence:       0.0,
				Services:         make(map[uint16]int),
				IsDNSServer:      false,
				DNSQueryCount:    0,
				DNSResponseCount: 0,
			}
		}

		// Initialize flow maps if not exists
		if _, exists := flows[t.SrcIP]; !exists {
			flows[t.SrcIP] = make(map[string]*FlowStats)
		}
		if _, exists := flows[t.SrcIP][t.DstIP]; !exists {
			flows[t.SrcIP][t.DstIP] = &FlowStats{
				FirstSeen: t.Timestamp,
				Ports:     make(map[uint16]int),
				Protocols: make(map[string]int),
			}
		}

		// Update flow statistics
		flow := flows[t.SrcIP][t.DstIP]
		flow.PacketCount++
		flow.ByteCount += int64(t.PacketSize)
		flow.LastSeen = t.Timestamp
		flow.Ports[t.DstPort]++
		flow.Protocols[t.Protocol]++

		// Track services by destination port for server identification
		if t.DstPort > 0 {
			dstNode := topology.Nodes[t.DstIP]
			dstNode.Services[t.DstPort]++

			// Track DNS specific information
			if t.IsDNS {
				// If it's a DNS query (client to server)
				if t.DstPort == 53 {
					dstNode.IsDNSServer = true
					dstNode.DNSQueryCount++
				}
				// If it's a DNS response (server to client)
				if t.SrcPort == 53 {
					srcNode := topology.Nodes[t.SrcIP]
					srcNode.IsDNSServer = true
					srcNode.DNSResponseCount++
				}
			}
		}
	}

	// Second pass: Analyze flow patterns and assign roles
	for srcIP, dstFlows := range flows {
		srcNode := topology.Nodes[srcIP]
		srcNode.Connections = len(dstFlows)

		for dstIP, flow := range dstFlows {
			// Initialize edge maps if not exists
			if _, exists := topology.Edges[srcIP]; !exists {
				topology.Edges[srcIP] = make(map[string]float64)
			}

			// Calculate connection strength based on flow statistics
			duration := flow.LastSeen.Sub(flow.FirstSeen).Seconds()
			if duration == 0 {
				duration = 1
			}

			strength := float64(flow.PacketCount) * float64(flow.ByteCount) / duration
			topology.Edges[srcIP][dstIP] = strength

			// Update node statistics
			srcNode.TotalTraffic += flow.ByteCount
		}
	}

	return topology
}

// Check if an IP is in private address space
func isPrivateIP(ip net.IP) bool {
	// Check the list of private IPv4 address ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateRanges {
		if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
			return true
		}
	}

	return false
}

// Helper function to return the maximum of two float64 values
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func applyFuzzyLogic(topology NetworkTopology) NetworkTopology {
	// Define fuzzy rules for node role classification
	for ip, node := range topology.Nodes {
		connectionScore := fuzzyConnectionScore(node.Connections)
		trafficScore := fuzzyTrafficScore(node.TotalTraffic)
		portPatternScore := fuzzyPortPatternScore(topology.Edges[ip])
		serviceScore := fuzzyServiceScore(node.Services)
		dnsScore := fuzzyDNSScore(node)

		// Check MAC-based role information
		macRoleScore := 0.0
		macBasedRole := ""

		if node.MAC != "" {
			if macRole, exists := topology.MACRoles[node.MAC]; exists {
				switch macRole {
				case "gateway":
					macRoleScore = 0.9
					macBasedRole = "gateway"
				case "multi-homed":
					macRoleScore = 0.7
					macBasedRole = "router"
				case "host":
					// For hosts, we'll still use connection-based analysis
					macRoleScore = 0.5
				}
			}
		}

		// Check for gateway patterns using connection analysis
		isGateway := detectGateway(ip, node, topology)

		// Combine scores using fuzzy rules
		serverScore := (connectionScore*0.25 + trafficScore*0.25 + portPatternScore*0.2 + serviceScore*0.2 + dnsScore*0.1)
		clientScore := (1-connectionScore)*0.35 + (1-trafficScore)*0.25 + (1-serviceScore)*0.25 + (1-dnsScore)*0.15
		routerScore := connectionScore*0.6 + (1-serviceScore)*0.3 + (1-dnsScore)*0.1
		dnsServerScore := dnsScore*0.6 + serviceScore*0.2 + connectionScore*0.2

		// When MAC analysis indicates a gateway, boost the gateway detection
		if macBasedRole == "gateway" && macRoleScore > 0.7 {
			isGateway = true
		}

		// Determine role based on highest score and thresholds
		if isGateway {
			node.Role = "gateway"
			// Use the higher confidence between the connection-based and MAC-based methods
			node.Confidence = max(0.9, macRoleScore)
		} else if node.IsDNSServer && dnsServerScore > 0.7 {
			node.Role = "dns-server"
			node.Confidence = dnsServerScore
		} else if macBasedRole == "router" && macRoleScore > 0.6 {
			// If MAC analysis strongly suggests a router
			node.Role = "router"
			node.Confidence = macRoleScore
		} else if serverScore > clientScore && serverScore > routerScore && serverScore > 0.6 {
			node.Role = "server"
			node.Confidence = serverScore
		} else if clientScore > serverScore && clientScore > routerScore && clientScore > 0.6 {
			node.Role = "client"
			node.Confidence = clientScore
		} else if routerScore > 0.7 {
			node.Role = "router"
			node.Confidence = routerScore
		} else {
			node.Role = "switch"
			node.Confidence = 0.5
		}
	}

	return topology
}

// fuzzyServiceScore evaluates how likely a node is a server based on its services
func fuzzyServiceScore(services map[uint16]int) float64 {
	if len(services) == 0 {
		return 0.0
	}

	// Common server ports
	serverPorts := map[uint16]bool{
		22:   true, // SSH
		23:   true, // Telnet
		25:   true, // SMTP
		53:   true, // DNS
		80:   true, // HTTP
		443:  true, // HTTPS
		3306: true, // MySQL
		5432: true, // PostgreSQL
		8080: true, // HTTP alt
		8443: true, // HTTPS alt
	}

	// Count server ports
	var serverPortCount, totalServices int
	var mostUsedPort uint16
	var mostUsedCount int

	for port, count := range services {
		if count > mostUsedCount {
			mostUsedCount = count
			mostUsedPort = port
		}

		totalServices += count
		if serverPorts[port] {
			serverPortCount += count
		}
	}

	// Calculate score: ratio of well-known server ports to total services
	if totalServices == 0 {
		return 0.0
	}

	ratio := float64(serverPortCount) / float64(totalServices)

	// Boost score if there's a dominant well-known port
	if serverPorts[mostUsedPort] && mostUsedCount > totalServices/2 {
		ratio += 0.2
		if ratio > 1.0 {
			ratio = 1.0
		}
	}

	return ratio
}

// analyzeMACRoles analyzes MAC to IP relationships to identify device roles
// Returns a map of MAC addresses to their likely roles
func analyzeMACRoles(macToIPs map[string]map[string]bool) map[string]string {
	macRoles := make(map[string]string)

	for mac, ips := range macToIPs {
		// If a MAC address is associated with many IP addresses,
		// it's likely to be a gateway or router
		if len(ips) > 3 {
			macRoles[mac] = "gateway"
		} else if len(ips) > 1 {
			// Multiple IPs but not many - could be a multi-homed host
			macRoles[mac] = "multi-homed"
		} else {
			// Single IP - likely a regular host
			macRoles[mac] = "host"
		}
	}

	return macRoles
}

// detectGateway identifies potential gateway devices in the network
func detectGateway(ip string, node *NetworkNode, topology NetworkTopology) bool {
	// If MAC is empty, fall back to connection-based heuristics
	if node.MAC == "" {
		return detectGatewayByConnections(ip, node, topology)
	}

	// Check if this MAC is considered a gateway from our MAC analysis
	if macRole, exists := topology.MACRoles[node.MAC]; exists && macRole == "gateway" {
		return true
	}

	// If not specifically identified as a gateway by MAC analysis,
	// fall back to connection-based heuristics
	return detectGatewayByConnections(ip, node, topology)
}

// detectGatewayByConnections uses connection patterns to identify gateways
func detectGatewayByConnections(ip string, node *NetworkNode, topology NetworkTopology) bool {
	// Skip nodes that don't have many connections
	if node.Connections < 5 {
		return false
	}

	// Gateway heuristics:
	// 1. Node has many connections
	// 2. Node communicates with both local and non-local addresses
	// 3. Often has a pattern of being the target of many connections from local subnet

	connectionsToLocal := 0
	connectionsToExternal := 0

	// Count edges to local vs external nodes
	if edges, exists := topology.Edges[ip]; exists {
		for dstIP := range edges {
			if dstNode, exists := topology.Nodes[dstIP]; exists {
				if dstNode.IsLocal {
					connectionsToLocal++
				} else {
					connectionsToExternal++
				}
			}
		}
	}

	// Check incoming connections too
	incomingFromLocal := 0
	incomingFromExternal := 0

	for srcIP, edges := range topology.Edges {
		if _, exists := edges[ip]; exists {
			if srcNode, exists := topology.Nodes[srcIP]; exists {
				if srcNode.IsLocal {
					incomingFromLocal++
				} else {
					incomingFromExternal++
				}
			}
		}
	}

	// Gateway conditions:
	// - Has both local and external connections
	// - More external connections than most nodes
	// - Many local nodes connect to it
	return (connectionsToLocal > 0 && connectionsToExternal > 3) ||
		(incomingFromLocal > 3 && connectionsToExternal > 1)
}

// Fuzzy logic helper functions
func fuzzyConnectionScore(connections int) float64 {
	// Higher score for nodes with more connections
	if connections <= 2 {
		return 0.2
	} else if connections <= 5 {
		return 0.5
	} else if connections <= 10 {
		return 0.8
	}
	return 1.0
}

func fuzzyTrafficScore(traffic int64) float64 {
	// Higher score for nodes with more traffic
	if traffic < 1000 {
		return 0.2
	} else if traffic < 10000 {
		return 0.5
	} else if traffic < 100000 {
		return 0.8
	}
	return 1.0
}

// fuzzyDNSScore evaluates how likely a node is a DNS server based on its DNS traffic
func fuzzyDNSScore(node *NetworkNode) float64 {
	if !node.IsDNSServer {
		return 0.0
	}

	// Calculate score based on DNS query and response counts
	totalDNS := node.DNSQueryCount + node.DNSResponseCount

	if totalDNS == 0 {
		return 0.0
	} else if totalDNS < 5 {
		return 0.3
	} else if totalDNS < 20 {
		return 0.6
	} else if totalDNS < 100 {
		return 0.8
	}
	return 1.0
}

func fuzzyPortPatternScore(edges map[string]float64) float64 {
	if len(edges) == 0 {
		return 0.0
	}

	// Calculate variance in connection strengths
	var sum, sqSum float64
	for _, strength := range edges {
		sum += strength
		sqSum += strength * strength
	}

	mean := sum / float64(len(edges))
	variance := (sqSum / float64(len(edges))) - (mean * mean)

	// Higher score for more consistent connection patterns
	if variance > 1000000 {
		return 0.2
	} else if variance > 100000 {
		return 0.5
	} else if variance > 10000 {
		return 0.8
	}
	return 1.0
}

// Print a summary of the inferred topology
func printTopologySummary(topology NetworkTopology) {
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

// generateTopologyVisualization creates a GraphViz DOT file visualization of the network topology
func generateTopologyVisualization(topology NetworkTopology, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Start DOT file
	fmt.Fprintln(file, "digraph NetworkTopology {")
	fmt.Fprintln(file, "  rankdir=TB;")
	fmt.Fprintln(file, "  node [shape=box, style=filled, fontname=\"Arial\"];")
	fmt.Fprintln(file, "  edge [fontname=\"Arial\"];")
	fmt.Fprintln(file, "  compound=true;")
	fmt.Fprintln(file, "  splines=true;")

	// Create a unique ID for each node to avoid special characters in node names
	nodeIDs := make(map[string]string)
	idCounter := 1

	// Define subnet clusters
	subnets := make(map[string][]string)
	for ip, node := range topology.Nodes {
		if node.Subnet != "" {
			subnets[node.Subnet] = append(subnets[node.Subnet], ip)
		}
	}

	// Define node colors based on role
	roleColors := map[string]string{
		"client":     "#A8E6CE", // Light green
		"server":     "#DCEDC2", // Light yellow-green
		"router":     "#FFD3B5", // Light orange
		"switch":     "#FFAAA6", // Light red
		"gateway":    "#FF8C94", // Salmon
		"dns-server": "#A8C0E6", // Light blue
	}

	// Create subnet clusters
	subnetCounter := 1
	for subnet, nodes := range subnets {
		fmt.Fprintf(file, "  subgraph cluster_%d {\n", subnetCounter)
		fmt.Fprintf(file, "    label=\"Subnet %s\";\n", subnet)
		fmt.Fprintf(file, "    style=filled;\n")
		fmt.Fprintf(file, "    color=\"#EEEEEE\";\n") // Light gray background

		// Add nodes to this subnet
		for _, ip := range nodes {
			node := topology.Nodes[ip]

			// Generate a unique ID for this node
			if _, exists := nodeIDs[ip]; !exists {
				nodeIDs[ip] = fmt.Sprintf("node%d", idCounter)
				idCounter++
			}

			// Select color based on role
			color := "#FFFFFF" // Default white
			if c, exists := roleColors[node.Role]; exists {
				color = c
			}

			// Format the node label with relevant information
			label := fmt.Sprintf("%s\\n%s", ip, node.Role)
			if node.MAC != "" {
				label += fmt.Sprintf("\\nMAC: %s", node.MAC)
			}

			// Add node to the graph
			fmt.Fprintf(file, "    %s [label=\"%s\", fillcolor=\"%s\"];\n",
				nodeIDs[ip], label, color)
		}

		fmt.Fprintln(file, "  }")
		subnetCounter++
	}

	// Add nodes without a subnet directly to the graph
	for ip, node := range topology.Nodes {
		if node.Subnet == "" {
			// Generate a unique ID for this node if not already done
			if _, exists := nodeIDs[ip]; !exists {
				nodeIDs[ip] = fmt.Sprintf("node%d", idCounter)
				idCounter++
			}

			// Select color based on role
			color := "#FFFFFF" // Default white
			if c, exists := roleColors[node.Role]; exists {
				color = c
			}

			// Format the node label
			label := fmt.Sprintf("%s\\n%s", ip, node.Role)
			if node.MAC != "" {
				label += fmt.Sprintf("\\nMAC: %s", node.MAC)
			}

			// Add node to the graph
			fmt.Fprintf(file, "  %s [label=\"%s\", fillcolor=\"%s\"];\n",
				nodeIDs[ip], label, color)
		}
	}

	// Add edges (connections between nodes)
	for srcIP, edges := range topology.Edges {
		if _, exists := nodeIDs[srcIP]; !exists {
			continue // Skip if source node doesn't exist
		}

		for dstIP, strength := range edges {
			if _, exists := nodeIDs[dstIP]; !exists {
				continue // Skip if destination node doesn't exist
			}

			// Edge thickness based on connection strength
			penwidth := 1.0
			if strength > 0 {
				// Normalize strength for visualization
				penwidth = math.Log10(strength) / 3.0
				if penwidth < 1.0 {
					penwidth = 1.0
				} else if penwidth > 5.0 {
					penwidth = 5.0
				}
			}

			// Add edge to the graph
			fmt.Fprintf(file, "  %s -> %s [penwidth=%.1f];\n",
				nodeIDs[srcIP], nodeIDs[dstIP], penwidth)
		}
	}

	// Add a legend
	fmt.Fprintln(file, "  subgraph cluster_legend {")
	fmt.Fprintln(file, "    label=\"Legend\";")
	fmt.Fprintln(file, "    style=filled;")
	fmt.Fprintln(file, "    color=\"#F5F5F5\";") // Very light gray

	legendCounter := 1
	for role, color := range roleColors {
		fmt.Fprintf(file, "    legend%d [label=\"%s\", fillcolor=\"%s\", shape=box];\n",
			legendCounter, role, color)
		legendCounter++
	}

	fmt.Fprintln(file, "  }")

	// Close the DOT file
	fmt.Fprintln(file, "}")

	return nil
}

func generateMininetTopology(topology NetworkTopology, outputFile string) error {
	const mininetTemplate = `#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def createTopology():
    # Create network with OVS switches and custom links
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, link=TCLink)
    
    # Add controller
    info('*** Adding controller\n')
    c0 = net.addController('c0')
    
    # Track switches by subnet
    switches = {}
    # Track router device
    router = None
    
    # Add a core switch
    info('*** Adding core switch\n')
    core_switch = net.addSwitch('s0')
    
    # Add subnet switches first
    info('*** Adding subnet switches\n')
    {{range $subnet, $_ := collectSubnets .Nodes}}
    # Create switch for subnet {{$subnet}}
    switches['{{$subnet}}'] = net.addSwitch('s{{formatSubnet $subnet}}')
    net.addLink(switches['{{$subnet}}'], core_switch)
    {{end}}
    
    # Add hosts
    info('*** Adding hosts\n')
    hosts = {}
    {{range $ip, $node := .Nodes}}
    {{if $node.IsLocal}}
    # Add host {{$ip}} ({{$node.Role}})
    {{if or (eq $node.Role "gateway") (eq $node.Role "router")}}
    if router is None:
        router = net.addHost('r{{formatIP $ip}}', ip='{{$ip}}')
        # Connect router to core switch
        net.addLink(router, core_switch)
    {{else if eq $node.Role "dns-server"}}
    # Add DNS server with custom configuration
    hosts['{{$ip}}'] = net.addHost('dns{{formatIP $ip}}', ip='{{$ip}}', mac='{{formatMAC $node.MAC}}')
    {{if $node.Subnet}}
    # Connect to subnet switch
    net.addLink(hosts['{{$ip}}'], switches['{{$node.Subnet}}'])
    {{else}}
    # No subnet, connect to core
    net.addLink(hosts['{{$ip}}'], core_switch)
    {{end}}
    {{else}}
    hosts['{{$ip}}'] = net.addHost('h{{formatIP $ip}}', ip='{{$ip}}', mac='{{formatMAC $node.MAC}}')
    {{if $node.Subnet}}
    # Connect to subnet switch
    net.addLink(hosts['{{$ip}}'], switches['{{$node.Subnet}}'])
    {{else}}
    # No subnet, connect to core
    net.addLink(hosts['{{$ip}}'], core_switch)
    {{end}}
    {{end}}
    {{end}}
    {{end}}
    
    # Add Internet host to simulate external traffic if we have a gateway
    {{if hasGateway .Nodes}}
    internet = net.addHost('internet', ip='8.8.8.8')
    net.addLink(internet, core_switch)
    {{end}}
    
    # Add external DNS server if needed
    {{if hasDNSServer .Nodes}}
    # Configure DNS servers to respond to queries
    info('*** Configuring DNS servers\n')
    {{range $ip, $node := .Nodes}}
    {{if and $node.IsLocal (eq $node.Role "dns-server")}}
    info('*** Setting up DNS server {{$ip}}\n')
    # Configure the hosts to use this DNS server
    for host in hosts.values():
        if host.IP() != '{{$ip}}':
            host.cmd('echo "nameserver {{$ip}}" > /etc/resolv.conf')
    {{end}}
    {{end}}
    {{end}}
    
    return net

# Helper functions for the template
def collectSubnets(nodes):
    subnets = {}
    for node in nodes.values():
        if node['Subnet'] and node['IsLocal']:
            subnets[node['Subnet']] = True
    return subnets

def formatSubnet(subnet):
    # Clean up subnet string to use as part of switch name
    return subnet.replace('.', '_').replace('/', '_')
    
def formatIP(ip):
    # Clean up IP string to use as part of host name
    return ip.replace('.', '_')
    
def formatMAC(mac):
    # Handle empty MAC addresses
    if not mac:
        return None
    return mac
    
def hasGateway(nodes):
    for node in nodes.values():
        if node['Role'] == 'gateway':
            return True
    return False

if __name__ == '__main__':
    setLogLevel('info')
    net = createTopology()
    net.start()
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()`

	// Add custom template functions
	funcMap := template.FuncMap{
		"collectSubnets": func(nodes map[string]*NetworkNode) map[string]bool {
			subnets := make(map[string]bool)
			for _, node := range nodes {
				if node.Subnet != "" && node.IsLocal {
					subnets[node.Subnet] = true
				}
			}
			return subnets
		},
		"formatSubnet": func(subnet string) string {
			return strings.NewReplacer(".", "_", "/", "_").Replace(subnet)
		},
		"formatIP": func(ip string) string {
			return strings.ReplaceAll(ip, ".", "_")
		},
		"formatMAC": func(mac string) string {
			if mac == "" {
				return ""
			}
			return mac
		},
		"hasGateway": func(nodes map[string]*NetworkNode) bool {
			for _, node := range nodes {
				if node.Role == "gateway" {
					return true
				}
			}
			return false
		},
		"hasDNSServer": func(nodes map[string]*NetworkNode) bool {
			for _, node := range nodes {
				if node.Role == "dns-server" {
					return true
				}
			}
			return false
		},
		"eq": func(a, b string) bool {
			return a == b
		},
		"or": func(a, b bool) bool {
			return a || b
		},
	}

	tmpl, err := template.New("mininet").Funcs(funcMap).Parse(mininetTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	err = tmpl.Execute(file, topology)
	if err != nil {
		return err
	}

	// Make the file executable
	err = os.Chmod(outputFile, 0755)
	if err != nil {
		log.Printf("Warning: Could not make topology file executable: %v", err)
	}

	return nil
}
