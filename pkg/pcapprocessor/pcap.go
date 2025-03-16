package pcapprocessor

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
)

// ParsePCAP parses a PCAP file and returns a slice of Traffic entries
func ParsePCAP(filename string) ([]analyzer.Traffic, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var traffic []analyzer.Traffic
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Use our analyzer package's ProcessPacket function
		t := analyzer.ProcessPacket(packet)
		
		// Skip packets without IP information
		if t.SrcIP == "" || t.DstIP == "" {
			continue
		}
		
		traffic = append(traffic, t)
	}

	return traffic, nil
}