package visualization

import (
	"fmt"
	"math"
	"os"
	"strings"
	"text/template"

	"github.com/trvon/pcap-to-mininet/pkg/analyzer"
)

// GenerateTopologyVisualization creates a GraphViz DOT file visualization of the network topology
func GenerateTopologyVisualization(topology analyzer.NetworkTopology, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Start DOT file
	fmt.Fprintln(file, "digraph NetworkTopology {")
	fmt.Fprintln(file, "  rankdir=TB;")
	fmt.Fprintln(file, "  node [shape=box, style=filled, fontname=\"Arial\"];")
	fmt.Fprintln(file, "  edge [fontname=\"Arial\"];")
	fmt.Fprintln(file, "  compound=true;")
	fmt.Fprintln(file, "  splines=true;")

	// Create a unique ID for each node to avoid special characters in node names
	nodeIDs := make(map[string]string)
	idCounter := 1

	// Define subnet clusters
	subnets := make(map[string][]string)
	for ip, node := range topology.Nodes {
		if node.Subnet != "" {
			subnets[node.Subnet] = append(subnets[node.Subnet], ip)
		}
	}

	// Define node colors based on role
	roleColors := map[string]string{
		"client":     "#A8E6CE", // Light green
		"server":     "#DCEDC2", // Light yellow-green
		"router":     "#FFD3B5", // Light orange
		"switch":     "#FFAAA6", // Light red
		"gateway":    "#FF8C94", // Salmon
		"dns-server": "#A8C0E6", // Light blue
	}

	// Create subnet clusters
	subnetCounter := 1
	for subnet, nodes := range subnets {
		fmt.Fprintf(file, "  subgraph cluster_%d {\n", subnetCounter)
		fmt.Fprintf(file, "    label=\"Subnet %s\";\n", subnet)
		fmt.Fprintf(file, "    style=filled;\n")
		fmt.Fprintf(file, "    color=\"#EEEEEE\";\n") // Light gray background

		// Add nodes to this subnet
		for _, ip := range nodes {
			node := topology.Nodes[ip]

			// Generate a unique ID for this node
			if _, exists := nodeIDs[ip]; !exists {
				nodeIDs[ip] = fmt.Sprintf("node%d", idCounter)
				idCounter++
			}

			// Select color based on role
			color := "#FFFFFF" // Default white
			if c, exists := roleColors[node.Role]; exists {
				color = c
			}

			// Format the node label with relevant information
			label := fmt.Sprintf("%s\\n%s", ip, node.Role)
			if node.MAC != "" {
				label += fmt.Sprintf("\\nMAC: %s", node.MAC)
			}

			// Add node to the graph
			fmt.Fprintf(file, "    %s [label=\"%s\", fillcolor=\"%s\"];\n",
				nodeIDs[ip], label, color)
		}

		fmt.Fprintln(file, "  }")
		subnetCounter++
	}

	// Add nodes without a subnet directly to the graph
	for ip, node := range topology.Nodes {
		if node.Subnet == "" {
			// Generate a unique ID for this node if not already done
			if _, exists := nodeIDs[ip]; !exists {
				nodeIDs[ip] = fmt.Sprintf("node%d", idCounter)
				idCounter++
			}

			// Select color based on role
			color := "#FFFFFF" // Default white
			if c, exists := roleColors[node.Role]; exists {
				color = c
			}

			// Format the node label
			label := fmt.Sprintf("%s\\n%s", ip, node.Role)
			if node.MAC != "" {
				label += fmt.Sprintf("\\nMAC: %s", node.MAC)
			}

			// Add node to the graph
			fmt.Fprintf(file, "  %s [label=\"%s\", fillcolor=\"%s\"];\n",
				nodeIDs[ip], label, color)
		}
	}

	// Add edges (connections between nodes)
	for srcIP, edges := range topology.Edges {
		if _, exists := nodeIDs[srcIP]; !exists {
			continue // Skip if source node doesn't exist
		}

		for dstIP, strength := range edges {
			if _, exists := nodeIDs[dstIP]; !exists {
				continue // Skip if destination node doesn't exist
			}

			// Edge thickness based on connection strength
			penwidth := 1.0
			if strength > 0 {
				// Normalize strength for visualization
				penwidth = math.Log10(strength) / 3.0
				if penwidth < 1.0 {
					penwidth = 1.0
				} else if penwidth > 5.0 {
					penwidth = 5.0
				}
			}

			// Add edge to the graph
			fmt.Fprintf(file, "  %s -> %s [penwidth=%.1f];\n",
				nodeIDs[srcIP], nodeIDs[dstIP], penwidth)
		}
	}

	// Add a legend
	fmt.Fprintln(file, "  subgraph cluster_legend {")
	fmt.Fprintln(file, "    label=\"Legend\";")
	fmt.Fprintln(file, "    style=filled;")
	fmt.Fprintln(file, "    color=\"#F5F5F5\";") // Very light gray

	legendCounter := 1
	for role, color := range roleColors {
		fmt.Fprintf(file, "    legend%d [label=\"%s\", fillcolor=\"%s\", shape=box];\n",
			legendCounter, role, color)
		legendCounter++
	}

	fmt.Fprintln(file, "  }")

	// Close the DOT file
	fmt.Fprintln(file, "}")

	return nil
}

// GenerateMininetTopology creates a Mininet Python script from the inferred network topology
func GenerateMininetTopology(topology analyzer.NetworkTopology, outputFile string) error {
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
		"collectSubnets": func(nodes map[string]*analyzer.NetworkNode) map[string]bool {
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
		"hasGateway": func(nodes map[string]*analyzer.NetworkNode) bool {
			for _, node := range nodes {
				if node.Role == "gateway" {
					return true
				}
			}
			return false
		},
		"hasDNSServer": func(nodes map[string]*analyzer.NetworkNode) bool {
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
		return fmt.Errorf("could not make topology file executable: %v", err)
	}

	return nil
}