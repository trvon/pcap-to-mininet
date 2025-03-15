package main

import (
    "bytes"
    "flag"
    "fmt"
    "log"
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
    IP                string
    MAC               string
    Subnet            string
    IsLocal           bool    // Whether this node is part of the local network
    Role              string  // "client", "server", "switch", "router", "gateway", "dns-server"
    Confidence        float64 // Fuzzy confidence score
    Connections       int     // Number of unique connections
    TotalTraffic      int64   // Total bytes transferred
    Services          map[uint16]int // Common ports used (for server identification)
    IsDNSServer       bool    // Whether this node acts as a DNS server
    DNSQueryCount     int     // Number of DNS queries handled
    DNSResponseCount  int     // Number of DNS responses sent
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
    pcapFile := flag.String("pcap", "", "PCAP file to analyze")
    pcapDir := flag.String("dir", "", "Directory containing PCAP files to analyze")
    outputFile := flag.String("output", "mininet_topology.py", "Output topology file")
    verbose := flag.Bool("verbose", false, "Enable verbose output")
    flag.Parse()
    
    // Validate input flags
    if *pcapFile == "" && *pcapDir == "" {
        log.Fatal("Either --pcap or --dir must be specified")
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
        Nodes: make(map[string]*NetworkNode),
        Edges: make(map[string]map[string]float64),
    }

    // Get subnet information
    subnets := identifySubnets(trafficData)
    
    // Create IP to MAC mapping
    ipToMAC := make(map[string]string)
    for _, t := range trafficData {
        if t.SrcMAC != "" && t.SrcIP != "" {
            ipToMAC[t.SrcIP] = t.SrcMAC
        }
        if t.DstMAC != "" && t.DstIP != "" {
            ipToMAC[t.DstIP] = t.DstMAC
        }
    }
    
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

func applyFuzzyLogic(topology NetworkTopology) NetworkTopology {
    // Define fuzzy rules for node role classification
    for ip, node := range topology.Nodes {
        connectionScore := fuzzyConnectionScore(node.Connections)
        trafficScore := fuzzyTrafficScore(node.TotalTraffic)
        portPatternScore := fuzzyPortPatternScore(topology.Edges[ip])
        serviceScore := fuzzyServiceScore(node.Services)
        dnsScore := fuzzyDNSScore(node)

        // Check for gateway patterns
        isGateway := detectGateway(ip, node, topology)
        
        // Combine scores using fuzzy rules
        serverScore := (connectionScore*0.25 + trafficScore*0.25 + portPatternScore*0.2 + serviceScore*0.2 + dnsScore*0.1)
        clientScore := (1 - connectionScore)*0.35 + (1 - trafficScore)*0.25 + (1 - serviceScore)*0.25 + (1 - dnsScore)*0.15
        routerScore := connectionScore*0.6 + (1 - serviceScore)*0.3 + (1 - dnsScore)*0.1
        dnsServerScore := dnsScore*0.6 + serviceScore*0.2 + connectionScore*0.2

        // Determine role based on highest score and thresholds
        if isGateway {
            node.Role = "gateway"
            node.Confidence = 0.9
        } else if node.IsDNSServer && dnsServerScore > 0.7 {
            node.Role = "dns-server"
            node.Confidence = dnsServerScore
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
        22: true,    // SSH
        23: true,    // Telnet
        25: true,    // SMTP
        53: true,    // DNS
        80: true,    // HTTP
        443: true,   // HTTPS
        3306: true,  // MySQL
        5432: true,  // PostgreSQL
        8080: true,  // HTTP alt
        8443: true,  // HTTPS alt
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

// detectGateway identifies potential gateway devices in the network
func detectGateway(ip string, node *NetworkNode, topology NetworkTopology) bool {
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
