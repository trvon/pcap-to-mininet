package analyzer

import (
	"bytes"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TimePoint is an alias for time.Time to keep backward compatibility
type TimePoint = time.Time

// Traffic represents a network traffic entry with enhanced metadata
type Traffic struct {
	SrcMAC       string
	DstMAC       string
	SrcIP        string
	DstIP        string
	Protocol     string
	SrcPort      uint16
	DstPort      uint16
	Timestamp    TimePoint
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

// Process a packet and return Traffic information
func ProcessPacket(packet gopacket.Packet) Traffic {
	t := Traffic{
		Timestamp:  packet.Metadata().Timestamp,
		PacketSize: len(packet.Data()),
	}

	// Extract Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		t.SrcMAC = eth.SrcMAC.String()
		t.DstMAC = eth.DstMAC.String()
	}

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		t.SrcIP = ip.SrcIP.String()
		t.DstIP = ip.DstIP.String()
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		t.SrcIP = ip.SrcIP.String()
		t.DstIP = ip.DstIP.String()
	}

	// Extract TCP/UDP layer
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

		// Check for DNS
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

	return t
}

// ProcessDNSTraffic updates the topology with DNS-specific information
func ProcessDNSTraffic(topology NetworkTopology, t Traffic) {
	if !t.IsDNS {
		return
	}

	// Track DNS specific information
	if t.DstPort == 53 {
		dstNode := topology.Nodes[t.DstIP]
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

// ApplyFuzzyLogic refines the topology using fuzzy logic
func ApplyFuzzyLogic(topology NetworkTopology) NetworkTopology {
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

// Helper function to return the maximum of two float64 values
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
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

// Check if an IP is in private address space
func IsPrivateIP(ip net.IP) bool {
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