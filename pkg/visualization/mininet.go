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
    # Processing node {{$ip}} ({{$node.Role}})
    {{if eq $node.Role "switch"}}
    # Skipping host creation for switch node {{$ip}}
    # L2 connectivity handled by OVSSwitch instances
    {{else if or (eq $node.Role "gateway") (eq $node.Role "router")}}
    # Add router/gateway (only creates one instance currently)
    if router is None:
        router = net.addHost('r{{formatIP $ip}}', ip='{{$ip}}')
        # Connect router to core switch
            net.addLink(router, core_switch)
    {{else if eq $node.Role "dns-server"}}
    # Add DNS server host
    hosts['{{$ip}}'] = net.addHost('dns{{formatIP $ip}}', ip='{{$ip}}', mac='{{formatMAC $node.MAC}}')
    {{if $node.Subnet}}
    net.addLink(hosts['{{$ip}}'], switches['{{$node.Subnet}}'])
    {{else}}
    net.addLink(hosts['{{$ip}}'], core_switch)
    {{end}}
    {{else}}
    # Add other hosts (client, server, etc.)
    hosts['{{$ip}}'] = net.addHost('h{{formatIP $ip}}', ip='{{$ip}}', mac='{{formatMAC $node.MAC}}')
    {{if $node.Subnet}}
    net.addLink(hosts['{{$ip}}'], switches['{{$node.Subnet}}'])
    {{else}}
    net.addLink(hosts['{{$ip}}'], core_switch)
    {{end}}
    {{end}} {{/* End of role checks */}}
    {{end}} {{/* End of IsLocal check */}}
    {{end}} {{/* End of node range */}}
    
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
    
    # --- Dump Topology to JSON ---
    info('*** Dumping topology to JSON\n')
    topo_data = {'nodes': [], 'links': []}
    # Add hosts
    for host in net.hosts:
        # Ensure host has an IP before adding
        host_ip = host.IP()
        if host_ip:
             node_info = {
                 'id': host.name,
                 'isHost': True,
                 'mac': host.MAC(),
                 'ip': host_ip + '/24' # Assuming /24, might need adjustment
             }
             topo_data['nodes'].append(node_info)
        else:
             info(f'*** Skipping host {host.name} with no IP for JSON dump\n')

    # Add switches
    for switch in net.switches:
        node_info = {
            'id': switch.name,
            'isP4Switch': True # Assume P4 switch for compatibility
            # Add other switch info if available/needed
        }
        topo_data['nodes'].append(node_info)

    # Add links
    link_id_counter = 0
    for link in net.links:
        try:
            node1 = link.intf1.node.name
            node2 = link.intf2.node.name
            # Use intf.name which should be reliable
            intfName1 = link.intf1.name
            intfName2 = link.intf2.name
            # Get ports - might fail if not set, default to 0
            port1 = link.intf1.node.ports.get(link.intf1, 0)
            port2 = link.intf2.node.ports.get(link.intf2, 0)
            addr1 = link.intf1.MAC()
            addr2 = link.intf2.MAC()
            ip1 = link.intf1.IP()
            ip2 = link.intf2.IP()

            link_info = {
                'id': f'link_{link_id_counter}',
                'node1': node1,
                'node2': node2,
                'port1': port1,
                'port2': port2,
                'addr1': addr1,
                'addr2': addr2,
                'intfName1': intfName1,
                'intfName2': intfName2,
                'ip1': f"{ip1}/24" if ip1 else None, # Assuming /24
                'ip2': f"{ip2}/24" if ip2 else None, # Assuming /24
            }
            topo_data['links'].append(link_info)
            link_id_counter += 1
        except Exception as link_err:
             info(f'*** Error processing link {link}: {link_err}\n')


    # Write to topology.json in the project root directory
    import json
    import os
    # Determine project root relative to the script location (assuming script is in env/)
    script_path = os.path.abspath(__file__)
    env_dir = os.path.dirname(script_path)
    project_root = os.path.dirname(env_dir)
    json_path = os.path.join(project_root, 'topology.json') # Output to root
    try:
        with open(json_path, 'w') as f:
            json.dump(topo_data, f, indent=4)
        info(f'*** Topology dumped to {json_path}\n')
    except Exception as e:
        info(f'*** Error dumping topology to JSON: {e}\n')
    # --- End Dump Topology ---

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
