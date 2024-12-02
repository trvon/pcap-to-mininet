package main

import (
    "fmt"
    "log"
    "os"
    "sort"
    "text/template"
    "time"
    
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

// Traffic represents a network traffic entry with enhanced metadata
type Traffic struct {
    SrcIP        string
    DstIP        string
    Protocol     string
    Port         uint16
    Timestamp    time.Time
    PacketSize   int
    FlowDuration time.Duration
}

// NetworkNode represents a node in the network with additional properties
type NetworkNode struct {
    IP           string
    Role         string  // "client", "server", "switch", "router"
    Confidence   float64 // Fuzzy confidence score
    Connections  int     // Number of unique connections
    TotalTraffic int64   // Total bytes transferred
}

// NetworkTopology represents the inferred network topology
type NetworkTopology struct {
    Nodes map[string]*NetworkNode
    Edges map[string]map[string]float64 // Source -> Destination -> Connection strength
}

// FlowStats keeps track of flow statistics between node pairs
type FlowStats struct {
    PacketCount  int
    ByteCount    int64
    FirstSeen    time.Time
    LastSeen     time.Time
    Ports        map[uint16]int
    Protocols    map[string]int
}

func main() {
    trafficData, err := parsePCAP("capture.pcap")
    if err != nil {
        log.Fatal(err)
    }

    topology := inferTopology(trafficData)
    refinedTopology := applyFuzzyLogic(topology)
    
    err = generateMininetTopology(refinedTopology, "mininet_topology.py")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Mininet topology generated successfully.")
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

        // Extract IP layer information
        if ipLayer := packet.Layer(gopacket.LayerTypeIPv4); ipLayer != nil {
            ip, _ := ipLayer.(*gopacket.layers.IPv4)
            t.SrcIP = ip.SrcIP.String()
            t.DstIP = ip.DstIP.String()
        }

        // Extract TCP/UDP layer information
        if tcpLayer := packet.Layer(gopacket.LayerTypeTCP); tcpLayer != nil {
            tcp, _ := tcpLayer.(*gopacket.layers.TCP)
            t.Protocol = "TCP"
            t.Port = uint16(tcp.DstPort)
        } else if udpLayer := packet.Layer(gopacket.LayerTypeUDP); udpLayer != nil {
            udp, _ := udpLayer.(*gopacket.layers.UDP)
            t.Protocol = "UDP"
            t.Port = uint16(udp.DstPort)
        }

        traffic = append(traffic, t)
    }
    
    return traffic, nil
}

func inferTopology(trafficData []Traffic) NetworkTopology {
    topology := NetworkTopology{
        Nodes: make(map[string]*NetworkNode),
        Edges: make(map[string]map[string]float64),
    }

    // Track flow statistics
    flows := make(map[string]map[string]*FlowStats)

    // First pass: Collect flow statistics
    for _, t := range trafficData {
        // Initialize node if not exists
        if _, exists := topology.Nodes[t.SrcIP]; !exists {
            topology.Nodes[t.SrcIP] = &NetworkNode{
                IP:         t.SrcIP,
                Confidence: 0.0,
            }
        }
        if _, exists := topology.Nodes[t.DstIP]; !exists {
            topology.Nodes[t.DstIP] = &NetworkNode{
                IP:         t.DstIP,
                Confidence: 0.0,
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
        flow.Ports[t.Port]++
        flow.Protocols[t.Protocol]++
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

func applyFuzzyLogic(topology NetworkTopology) NetworkTopology {
    // Define fuzzy rules for node role classification
    for ip, node := range topology.Nodes {
        connectionScore := fuzzyConnectionScore(node.Connections)
        trafficScore := fuzzyTrafficScore(node.TotalTraffic)
        portPatternScore := fuzzyPortPatternScore(topology.Edges[ip])

        // Combine scores using fuzzy rules
        serverScore := (connectionScore*0.4 + trafficScore*0.4 + portPatternScore*0.2)
        clientScore := (1 - connectionScore)*0.5 + (1 - trafficScore)*0.3 + (1 - portPatternScore)*0.2

        if serverScore > clientScore && serverScore > 0.6 {
            node.Role = "server"
            node.Confidence = serverScore
        } else if clientScore > 0.6 {
            node.Role = "client"
            node.Confidence = clientScore
        } else {
            node.Role = "switch"
            node.Confidence = 0.5
        }
    }

    return topology
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
    variance := (sqSum/float64(len(edges))) - (mean * mean)
    
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

func generateMininetTopology(topology NetworkTopology, outputFile string) error {
    const mininetTemplate = `#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def createTopology():
    net = Mininet(controller=Controller, switch=OVSSwitch)
    
    # Add controller
    c0 = net.addController('c0')
    
    # Add switches for routing
    s1 = net.addSwitch('s1')
    
    # Add hosts
    hosts = {}
    {{range $ip, $node := .Nodes}}
    hosts['{{$ip}}'] = net.addHost('h{{$ip}}', ip='{{$ip}}')
    {{end}}
    
    # Add links
    {{range $src, $dsts := .Edges}}
    {{range $dst, $strength := $dsts}}
    net.addLink(hosts['{{$src}}'], s1)
    net.addLink(hosts['{{$dst}}'], s1)
    {{end}}
    {{end}}
    
    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = createTopology()
    net.start()
    CLI(net)
    net.stop()`

    tmpl, err := template.New("mininet").Parse(mininetTemplate)
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

    return nil
}1