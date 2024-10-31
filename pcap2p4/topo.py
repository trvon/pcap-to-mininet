#!/usr/bin/python3
import os
import sys
import time
from scapy.all import rdpcap, IP, Ether
from collections import defaultdict
from p4utils.mininetlib.network_API import NetworkAPI
import networkx as nx
from typing import Dict, Set, Tuple, List

class PcapTopologyMapper:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.flow_stats = defaultdict(int)
        self.node_connections = defaultdict(set)
        self.ingress_nodes = set()
        self.egress_nodes = set()
        self.G = nx.Graph()
        
    def analyze_pcap(self) -> None:
        """Analyze PCAP file to extract flow statistics and node connections"""
        packets = rdpcap(self.pcap_file)
        
        for packet in packets:
            if IP in packet and Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Track Layer 2 connections
                self.node_connections[src_mac].add(dst_mac)
                
                # Track flow statistics
                flow_key = (src_ip, dst_ip)
                self.flow_stats[flow_key] += 1
                
                # Identify potential ingress/egress nodes
                self._update_edge_nodes(src_mac, dst_mac)
    
    def _update_edge_nodes(self, src_mac: str, dst_mac: str) -> None:
        """Update ingress and egress node sets based on traffic patterns"""
        if not any(src_mac in conns for conns in self.node_connections.values()):
            self.ingress_nodes.add(src_mac)
        if not self.node_connections[dst_mac]:
            self.egress_nodes.add(dst_mac)
    
    def map_to_p4_topology(self, net: NetworkAPI) -> Dict:
        """Map the analyzed traffic to P4 switches in the topology"""
        topology_mapping = {
            'int_sources': [],
            'int_sinks': [],
            'flow_paths': defaultdict(list)
        }
        
        # Map ingress/egress nodes to P4 switches
        switches = [f"s{i}" for i in range(1, 6)]
        
        # Identify INT source switches (switches connected to high-traffic ingress nodes)
        sorted_ingress = sorted(self.ingress_nodes, 
                              key=lambda x: sum(self.flow_stats[k] for k in self.flow_stats 
                                              if x in k),
                              reverse=True)
        
        # Select top switches as INT sources
        topology_mapping['int_sources'] = [
            switch for switch in switches 
            if any(host in sorted_ingress[:2] for host in net.get_switch_intfs(switch))
        ]
        
        # Identify INT sink switches
        sorted_egress = sorted(self.egress_nodes,
                             key=lambda x: sum(self.flow_stats[k] for k in self.flow_stats 
                                             if x in k),
                             reverse=True)
        
        topology_mapping['int_sinks'] = [
            switch for switch in switches 
            if any(host in sorted_egress[:2] for host in net.get_switch_intfs(switch))
        ]
        
        return topology_mapping

def configure_network(net: NetworkAPI, topology_mapping: Dict) -> None:
    """Configure the P4 network based on the topology mapping"""
    # Configure INT source switches
    for source_switch in topology_mapping['int_sources']:
        net.setP4SourceParams(
            source_switch,
            int_source=True,
            int_config={
                'hop_metadata': True,
                'flow_metadata': True,
                'queue_metadata': True
            }
        )
    
    # Configure INT sink switches
    for sink_switch in topology_mapping['int_sinks']:
        net.setP4SourceParams(
            sink_switch,
            int_sink=True,
            collector_config={
                'ip': '127.0.0.1',
                'port': 54321,
                'protocol': 'UDP'
            }
        )

def main():
    try:
        # Initialize network
        cleanup()
        net = NetworkAPI()
        net.setLogLevel("info")
        
        # Create the original topology (your existing topology code here)
        # ... (keep your existing topology creation code)
        
        # Create and analyze topology mapping
        pcap_file = "path/to/your/dataset.pcap"  # Replace with actual path
        mapper = PcapTopologyMapper(pcap_file)
        mapper.analyze_pcap()
        
        # Map the analyzed traffic to P4 topology
        topology_mapping = mapper.map_to_p4_topology(net)
        
        # Configure the network with INT capabilities
        configure_network(net, topology_mapping)
        
        # Start the network
        net.startNetwork()
        
        # Print topology information
        print("\nTopology Mapping Results:")
        print(f"INT Source Switches: {topology_mapping['int_sources']}")
        print(f"INT Sink Switches: {topology_mapping['int_sinks']}")
        net.printPortMapping()
        
    except Exception as e:
        print(f"An error occurred: {e}")
        cleanup()
        sys.exit(1)

def cleanup():
    """Clean up any running instances"""
    os.system("sudo mn -c")

if __name__ == "__main__":
    main()

