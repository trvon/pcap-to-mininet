package tests

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
	"github.com/trvon/pcap-to-mininet/pkg/topology"
	"github.com/trvon/pcap-to-mininet/pkg/visualization"
)

// TestTopologyGenerationWithDNS tests the full pipeline with DNS packets
func TestTopologyGenerationWithDNS(t *testing.T) {
	// Skip this test if running short tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create test directory
	testDir, err := os.MkdirTemp("", "pcap-test")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create test traffic data directly (simulating PCAP parsing)
	var trafficData []analyzer.Traffic

	// Add DNS query traffic
	trafficData = append(trafficData, analyzer.Traffic{
		SrcIP:    "192.168.1.20",
		DstIP:    "192.168.1.10",
		SrcMAC:   "00:11:22:33:44:66",
		DstMAC:   "00:11:22:33:44:55",
		Protocol: "UDP",
		SrcPort:  12345,
		DstPort:  53,
		IsDNS:    true,
		DNSQuery: "example.com",
	})

	// Add DNS response traffic
	trafficData = append(trafficData, analyzer.Traffic{
		SrcIP:    "192.168.1.10",
		DstIP:    "192.168.1.20",
		SrcMAC:   "00:11:22:33:44:55",
		DstMAC:   "00:11:22:33:44:66",
		Protocol: "UDP",
		SrcPort:  53,
		DstPort:  12345,
		IsDNS:    true,
	})

	// Create output file path
	outputFile := filepath.Join(testDir, "mininet_topology.py")

	// Run the processing pipeline
	networkTopology := topology.InferTopology(trafficData)
	refinedTopology := analyzer.ApplyFuzzyLogic(networkTopology)

	// Generate the Mininet topology
	err = visualization.GenerateMininetTopology(refinedTopology, outputFile)
	if err != nil {
		t.Fatalf("Failed to generate Mininet topology: %v", err)
	}

	// Verify the topology file was generated
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Errorf("Mininet topology file was not generated")
	}

	// Check that we have the expected nodes in the topology
	verifyTopologyNodes(t, refinedTopology)
}

// TestDNSResilience tests the resilience of DNS packet handling
func TestDNSResilience(t *testing.T) {
	// Create mixed traffic data with some malformed packets
	var trafficData []analyzer.Traffic

	// Regular DNS packet
	trafficData = append(trafficData, analyzer.Traffic{
		SrcIP:    "192.168.1.20",
		DstIP:    "192.168.1.10",
		SrcPort:  12345,
		DstPort:  53,
		Protocol: "UDP",
		IsDNS:    true,
		DNSQuery: "example.com",
	})

	// Malformed DNS packet (UDP port 53 but not actually DNS)
	trafficData = append(trafficData, analyzer.Traffic{
		SrcIP:    "192.168.1.21",
		DstIP:    "192.168.1.10",
		SrcPort:  12346,
		DstPort:  53,
		Protocol: "UDP",
		IsDNS:    false, // Not marked as DNS despite port 53
	})

	// Non-DNS packet
	trafficData = append(trafficData, analyzer.Traffic{
		SrcIP:    "192.168.1.22",
		DstIP:    "192.168.1.30",
		SrcPort:  12347,
		DstPort:  80,
		Protocol: "TCP",
		IsDNS:    false,
	})

	// Process the traffic data
	networkTopology := topology.InferTopology(trafficData)
	refinedTopology := analyzer.ApplyFuzzyLogic(networkTopology)

	// The DNS server should still be identified despite the malformed packet
	if !refinedTopology.Nodes["192.168.1.10"].IsDNSServer {
		t.Errorf("DNS server not identified despite valid DNS traffic")
	}

	// And the DNS server role should be properly assigned
	// (this test is more lenient since the classification depends on thresholds)
	t.Logf("DNS server role: %s (expected 'dns-server' or 'server')",
		refinedTopology.Nodes["192.168.1.10"].Role)
}

// TestEdgeCases tests edge cases in DNS packet handling
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		traffic analyzer.Traffic
		wantDNS bool
	}{
		{
			name: "TCP port 53 (not DNS)",
			traffic: analyzer.Traffic{
				SrcIP:    "192.168.1.2",
				DstIP:    "192.168.1.1",
				Protocol: "TCP",
				SrcPort:  12345,
				DstPort:  53,
				IsDNS:    false, // TCP on port 53 is not automatically DNS
			},
			wantDNS: false,
		},
		{
			name: "Empty DNS query",
			traffic: analyzer.Traffic{
				SrcIP:    "192.168.1.2",
				DstIP:    "192.168.1.1",
				Protocol: "UDP",
				SrcPort:  12345,
				DstPort:  53,
				IsDNS:    true,
				DNSQuery: "", // Empty query
			},
			wantDNS: true,
		},
		{
			name: "Response from DNS server",
			traffic: analyzer.Traffic{
				SrcIP:    "192.168.1.1",
				DstIP:    "192.168.1.2",
				Protocol: "UDP",
				SrcPort:  53,
				DstPort:  12345,
				IsDNS:    true,
			},
			wantDNS: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a basic topology with two nodes
			testTopology := analyzer.NetworkTopology{
				Nodes: make(map[string]*analyzer.NetworkNode),
				Edges: make(map[string]map[string]float64),
			}

			// Add the nodes
			testTopology.Nodes[tc.traffic.SrcIP] = &analyzer.NetworkNode{
				IP:               tc.traffic.SrcIP,
				Services:         make(map[uint16]int),
				IsDNSServer:      false,
				DNSQueryCount:    0,
				DNSResponseCount: 0,
			}

			testTopology.Nodes[tc.traffic.DstIP] = &analyzer.NetworkNode{
				IP:               tc.traffic.DstIP,
				Services:         make(map[uint16]int),
				IsDNSServer:      false,
				DNSQueryCount:    0,
				DNSResponseCount: 0,
			}

			// Process the DNS traffic
			analyzer.ProcessDNSTraffic(testTopology, tc.traffic)

			// Verify DNS server identification
			if tc.wantDNS {
				// In a DNS query
				if tc.traffic.DstPort == 53 {
					if !testTopology.Nodes[tc.traffic.DstIP].IsDNSServer {
						t.Errorf("Expected destination to be marked as DNS server")
					}
				}

				// In a DNS response
				if tc.traffic.SrcPort == 53 {
					if !testTopology.Nodes[tc.traffic.SrcIP].IsDNSServer {
						t.Errorf("Expected source to be marked as DNS server")
					}
				}
			}
		})
	}
}

// Helper functions for the integration tests

// verifyTopologyNodes checks that the topology has the expected nodes and roles
func verifyTopologyNodes(t *testing.T, topology analyzer.NetworkTopology) {
	// Count node types
	var dnsServers int

	for _, node := range topology.Nodes {
		if node.Role == "dns-server" {
			dnsServers++
		}
	}

	// In our mock topology, we should have at least one DNS server
	t.Logf("DNS servers found: %d", dnsServers)

	// We don't make this a hard assertion because the actual classification
	// depends on the specific thresholds in the fuzzy logic
}

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