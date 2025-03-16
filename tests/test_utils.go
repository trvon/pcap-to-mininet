package tests

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GenerateMockDNSPacket creates a mock DNS packet for testing
func GenerateMockDNSPacket(domain string, isQuery bool) []byte {
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

// GenerateMockUDPPacket creates a non-DNS UDP packet for testing
func GenerateMockUDPPacket(srcPort, dstPort uint16) []byte {
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