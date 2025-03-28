package pcapprocessor

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
)

// ParsePCAP parses a PCAP file and returns a slice of Traffic entries and a set of unique MAC addresses
func ParsePCAP(filename string) ([]analyzer.Traffic, map[string]struct{}, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Close()

	var traffic []analyzer.Traffic
	uniqueMACs := make(map[string]struct{}) // Use map as a set for unique MACs
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Use our analyzer package's ProcessPacket function
		t := analyzer.ProcessPacket(packet)

		// Collect MAC addresses if they exist
		if t.SrcMAC != "" {
			uniqueMACs[t.SrcMAC] = struct{}{}
		}
		if t.DstMAC != "" {
			uniqueMACs[t.DstMAC] = struct{}{}
		}

		// Skip packets without IP information for topology inference, but keep MACs
		if t.SrcIP == "" || t.DstIP == "" {
			continue
		}

		traffic = append(traffic, t)
	}

	return traffic, uniqueMACs, nil
}
