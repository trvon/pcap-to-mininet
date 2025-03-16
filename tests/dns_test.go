package tests

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
)

// TestDNSPacketDetection tests that DNS packets are properly identified
func TestDNSPacketDetection(t *testing.T) {
	// Create a mock DNS packet
	buffer := GenerateMockDNSPacket("example.com", true)

	// Parse the packet
	packet := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)

	// Process the packet as the main code would
	traffic := analyzer.ProcessPacket(packet)

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
	buffer := GenerateMockUDPPacket(8080, 12345)

	// Parse the packet
	packet := gopacket.NewPacket(buffer, layers.LayerTypeEthernet, gopacket.Default)

	// Process the packet
	traffic := analyzer.ProcessPacket(packet)

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
	topology := analyzer.NetworkTopology{
		Nodes: make(map[string]*analyzer.NetworkNode),
		Edges: make(map[string]map[string]float64),
	}

	// Add a DNS server node
	dnsServer := &analyzer.NetworkNode{
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
	regularServer := &analyzer.NetworkNode{
		IP:       "192.168.1.20",
		MAC:      "00:11:22:33:44:66",
		IsLocal:  true,
		Subnet:   "192.168.1.0/24",
		Services: map[uint16]int{80: 100},
	}
	topology.Nodes["192.168.1.20"] = regularServer

	// Add a client node
	clientNode := &analyzer.NetworkNode{
		IP:          "192.168.1.30",
		MAC:         "00:11:22:33:44:77",
		IsLocal:     true,
		Subnet:      "192.168.1.0/24",
		Connections: 3,
	}
	topology.Nodes["192.168.1.30"] = clientNode

	// Apply fuzzy logic
	refinedTopology := analyzer.ApplyFuzzyLogic(topology)

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

// TestDNSTrafficTracking tests that DNS query/response counts are properly tracked
func TestDNSTrafficTracking(t *testing.T) {
	// Create a mock topology
	topology := analyzer.NetworkTopology{
		Nodes: make(map[string]*analyzer.NetworkNode),
		Edges: make(map[string]map[string]float64),
	}

	// Add DNS server and client nodes
	topology.Nodes["192.168.1.10"] = &analyzer.NetworkNode{
		IP:               "192.168.1.10",
		Services:         make(map[uint16]int),
		IsDNSServer:      false,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}

	topology.Nodes["192.168.1.20"] = &analyzer.NetworkNode{
		IP:               "192.168.1.20",
		Services:         make(map[uint16]int),
		IsDNSServer:      false,
		DNSQueryCount:    0,
		DNSResponseCount: 0,
	}

	// Create DNS query traffic (client to server)
	queryTraffic := analyzer.Traffic{
		SrcIP:   "192.168.1.20",
		DstIP:   "192.168.1.10",
		SrcPort: 12345,
		DstPort: 53,
		IsDNS:   true,
	}

	// Create DNS response traffic (server to client)
	responseTraffic := analyzer.Traffic{
		SrcIP:   "192.168.1.10",
		DstIP:   "192.168.1.20",
		SrcPort: 53,
		DstPort: 12345,
		IsDNS:   true,
	}

	// Process the traffic for DNS server tracking
	analyzer.ProcessDNSTraffic(topology, queryTraffic)
	analyzer.ProcessDNSTraffic(topology, responseTraffic)

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

// Helper functions for processing packets in tests are now in test_utils.go
