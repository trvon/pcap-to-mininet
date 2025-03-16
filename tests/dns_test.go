package main

import (
	"net"
	"testing"
	"github.com/trvon/pcap-to-mininet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestDNSPacketDetection tests that DNS packets are properly identified
func TestDNSPacketDetection(t *testing.T) {
	// Create a mock DNS packet
	buffer := generateMockDNSPacket("example.com", true)

	// Parse the packet
	packet := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)

	// Process the packet as the main code would
	traffic := processPacketForTest(packet)

	// Verify DNS packet identification
	if !traffic.IsDNS {
		t.Errorf("Failed to identify DNS packet: IsDNS is false")
	}

	// Verify DNS query extraction
	if traffic.DNSQuery != "example.com" {
		t.Errorf("Failed to extract DNS query name: got %s, want example.com", traffic.DNSQuery)
	}

	// Verify port identification
	if traffic.DstPort != 53 {
		t.Errorf("Incorrect destination port: got %d, want 53", traffic.DstPort)
	}
}

// TestNonDNSUDPPacket tests that non-DNS UDP packets are not misidentified
func TestNonDNSUDPPacket(t *testing.T) {
	// Create a mock UDP packet (not DNS)
	buffer := generateMockUDPPacket(8080, 12345)

	// Parse the packet
	packet := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)

	// Process the packet
	traffic := processPacketForTest(packet)

	// Verify it's not identified as DNS
	if traffic.IsDNS {
		t.Errorf("Non-DNS UDP packet incorrectly identified as DNS")
	}

	// Check ports for verification
	if traffic.SrcPort != 8080 || traffic.DstPort != 12345 {
		t.Errorf("Incorrect port information: src=%d, dst=%d", traffic.SrcPort, traffic.DstPort)
	}
}

// TestDNSServerDetection tests that the fuzzy logic correctly identifies DNS servers
func TestDNSServerDetection(t *testing.T) {
	// Create a mock topology with a DNS server
	topology := NetworkTopology{
		Nodes: make(map[string]*NetworkNode),
		Edges: make(map[string]map[string]float64),
	}

	// Add a DNS server node
	dnsServer := &NetworkNode{
		IP:               "192.168.1.10",
		MAC:              "00:11:22:33:44:55",
		IsLocal:          true,
		Subnet:           "192.168.1.0/24",
		IsDNSServer:      true,
		DNSQueryCount:    50,
		DNSResponseCount: 45,
		Services:         map[uint16]int{53: 95},
	}
	topology.Nodes["192.168.1.10"] = dnsServer

	// Add a regular server node
	regularServer := &NetworkNode{
		IP:       "192.168.1.20",
		MAC:      "00:11:22:33:44:66",
		IsLocal:  true,
		Subnet:   "192.168.1.0/24",
		Services: map[uint16]int{80: 100},
	}
	topology.Nodes["192.168.1.20"] = regularServer

	// Add a client node
	clientNode := &NetworkNode{
		IP:          "192.168.1.30",
		MAC:         "00:11:22:33:44:77",
		IsLocal:     true,
		Subnet:      "192.168.1.0/24",
		Connections: 3,
	}
	topology.Nodes["192.168.1.30"] = clientNode

	// Apply fuzzy logic
	refinedTopology := applyFuzzyLogic(topology)

	// Check DNS server role assignment
	if refinedTopology.Nodes["192.168.1.10"].Role != "dns-server" {
		t.Errorf("Failed to identify DNS server: got role %s", refinedTopology.Nodes["192.168.1.10"].Role)
	}

	// Check regular server
	if refinedTopology.Nodes["192.168.1.20"].Role != "server" &&
		refinedTopology.Nodes["192.168.1.20"].Role != "client" {
		t.Errorf("Incorrectly identified regular server: got role %s", refinedTopology.Nodes["192.168.1.20"].Role)
	}

	// Check that client is not misidentified
	if refinedTopology.Nodes["192.168.1.30"].Role == "dns-server" {
		t.Errorf("Client incorrectly identified as DNS server: got role %s", refinedTopology.Nodes["192.168.1.30"].Role)
	}
}

// TestDNSScoreFunction tests the fuzzyDNSScore function
func TestDNSScoreFunction(t *testing.T) {
	// Test case: not a DNS server
	nonDNSNode := &NetworkNode{
		IsDNSServer:      false,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}
	if score := fuzzyDNSScore(nonDNSNode); score != 0.0 {
		t.Errorf("Non-DNS server should have score 0, got %f", score)
	}

	// Test case: DNS server with no traffic
	emptyDNSNode := &NetworkNode{
		IsDNSServer:      true,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}
	if score := fuzzyDNSScore(emptyDNSNode); score != 0.0 {
		t.Errorf("DNS server with no traffic should have score 0, got %f", score)
	}

	// Test case: DNS server with low traffic
	lowDNSNode := &NetworkNode{
		IsDNSServer:      true,
		DNSQueryCount:    2,
		DNSResponseCount: 2,
	}
	if score := fuzzyDNSScore(lowDNSNode); score != 0.3 {
		t.Errorf("DNS server with low traffic should have score 0.3, got %f", score)
	}

	// Test case: DNS server with medium traffic
	mediumDNSNode := &NetworkNode{
		IsDNSServer:      true,
		DNSQueryCount:    8,
		DNSResponseCount: 7,
	}
	if score := fuzzyDNSScore(mediumDNSNode); score != 0.6 {
		t.Errorf("DNS server with medium traffic should have score 0.6, got %f", score)
	}

	// Test case: DNS server with high traffic
	highDNSNode := &NetworkNode{
		IsDNSServer:      true,
		DNSQueryCount:    45,
		DNSResponseCount: 40,
	}
	if score := fuzzyDNSScore(highDNSNode); score != 0.8 {
		t.Errorf("DNS server with high traffic should have score 0.8, got %f", score)
	}

	// Test case: DNS server with very high traffic
	veryHighDNSNode := &NetworkNode{
		IsDNSServer:      true,
		DNSQueryCount:    250,
		DNSResponseCount: 240,
	}
	if score := fuzzyDNSScore(veryHighDNSNode); score != 1.0 {
		t.Errorf("DNS server with very high traffic should have score 1.0, got %f", score)
	}
}

// TestDNSTrafficTracking tests that DNS query/response counts are properly tracked
func TestDNSTrafficTracking(t *testing.T) {
	// Create a mock topology
	topology := NetworkTopology{
		Nodes: make(map[string]*NetworkNode),
		Edges: make(map[string]map[string]float64),
	}

	// Add DNS server and client nodes
	topology.Nodes["192.168.1.10"] = &NetworkNode{
		IP:               "192.168.1.10",
		Services:         make(map[uint16]int),
		IsDNSServer:      false,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}

	topology.Nodes["192.168.1.20"] = &NetworkNode{
		IP:               "192.168.1.20",
		Services:         make(map[uint16]int),
		IsDNSServer:      false,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}

	// Create DNS query traffic (client to server)
	queryTraffic := Traffic{
		SrcIP:   "192.168.1.20",
		DstIP:   "192.168.1.10",
		SrcPort: 12345,
		DstPort: 53,
		IsDNS:   true,
	}

	// Create DNS response traffic (server to client)
	responseTraffic := Traffic{
		SrcIP:   "192.168.1.10",
		DstIP:   "192.168.1.20",
		SrcPort: 53,
		DstPort: 12345,
		IsDNS:   true,
	}

	// Process the traffic for DNS server tracking
	processDNSTrafficForTest(topology, queryTraffic)
	processDNSTrafficForTest(topology, responseTraffic)

	// Check if DNS server is properly identified
	if !topology.Nodes["192.168.1.10"].IsDNSServer {
		t.Errorf("Failed to mark node as DNS server")
	}

	// Check query count
	if topology.Nodes["192.168.1.10"].DNSQueryCount != 1 {
		t.Errorf("DNS query count incorrect: got %d, want 1",
			topology.Nodes["192.168.1.10"].DNSQueryCount)
	}

	// Check response count
	if topology.Nodes["192.168.1.10"].DNSResponseCount != 1 {
		t.Errorf("DNS response count incorrect: got %d, want 1",
			topology.Nodes["192.168.1.10"].DNSResponseCount)
	}
}

// Helper functions to create test packets and simulate processing

// generateMockDNSPacket creates a mock DNS packet for testing
func generateMockDNSPacket(domain string, isQuery bool) []byte {
	// Create the layers
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	if isQuery {
		ipv4.SrcIP = net.ParseIP("192.168.1.20")
		ipv4.DstIP = net.ParseIP("192.168.1.10")
	} else {
		ipv4.SrcIP = net.ParseIP("192.168.1.10")
		ipv4.DstIP = net.ParseIP("192.168.1.20")
	}

	udp := layers.UDP{}
	if isQuery {
		udp.SrcPort = layers.UDPPort(12345)
		udp.DstPort = layers.UDPPort(53)
	} else {
		udp.SrcPort = layers.UDPPort(53)
		udp.DstPort = layers.UDPPort(12345)
	}

	dns := layers.DNS{
		QR: !isQuery, // false for query, true for response
		RD: true,     // Recursion desired
		RA: !isQuery, // Recursion available (for responses)
	}

	if isQuery {
		dns.Questions = []layers.DNSQuestion{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		}
	} else {
		dns.Questions = []layers.DNSQuestion{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		}
		dns.Answers = []layers.DNSResourceRecord{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    net.ParseIP("93.184.216.34"),
			},
		}
	}

	// Calculate checksums and lengths
	udp.SetNetworkLayerForChecksum(&ipv4)

	// Serialize all layers into buffer
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		&eth,
		&ipv4,
		&udp,
		&dns,
	)

	if err != nil {
		panic(err) // In a test, we can just panic
	}

	return buffer.Bytes()
}

// generateMockUDPPacket creates a non-DNS UDP packet for testing
func generateMockUDPPacket(srcPort, dstPort uint16) []byte {
	// Create the layers
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.20"),
		DstIP:    net.ParseIP("192.168.1.30"),
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	// Calculate checksums and lengths
	udp.SetNetworkLayerForChecksum(&ipv4)

	// Serialize all layers into buffer
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		&eth,
		&ipv4,
		&udp,
	)

	if err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

// processPacketForTest simulates the packet processing logic from parsePCAP
func processPacketForTest(packet gopacket.Packet) Traffic {
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

// processDNSTrafficForTest simulates the DNS tracking logic
func processDNSTrafficForTest(topology NetworkTopology, t Traffic) {
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
