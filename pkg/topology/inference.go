package topology

import (
	"fmt"
	"net"
	"strings"
	
	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
)

// IdentifySubnets analyzes traffic data to identify subnets
func IdentifySubnets(trafficData []analyzer.Traffic) map[string]int {
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

// InferTopology analyzes traffic data to infer network topology
func InferTopology(trafficData []analyzer.Traffic) analyzer.NetworkTopology {
	topology := analyzer.NetworkTopology{
		Nodes:    make(map[string]*analyzer.NetworkNode),
		Edges:    make(map[string]map[string]float64),
		MACRoles: make(map[string]string),
	}

	// Get subnet information
	subnets := IdentifySubnets(trafficData)

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
						isLocal = analyzer.IsPrivateIP(srcIP)
					}
				}
			}

			topology.Nodes[t.SrcIP] = &analyzer.NetworkNode{
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
						isLocal = analyzer.IsPrivateIP(dstIP)
					}
				}
			}

			topology.Nodes[t.DstIP] = &analyzer.NetworkNode{
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

			// Process DNS information
			analyzer.ProcessDNSTraffic(topology, t)
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

// FlowStats keeps track of flow statistics between node pairs
type FlowStats struct {
	PacketCount int
	ByteCount   int64
	FirstSeen   analyzer.TimePoint
	LastSeen    analyzer.TimePoint
	Ports       map[uint16]int
	Protocols   map[string]int
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