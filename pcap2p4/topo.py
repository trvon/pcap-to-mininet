#!/usr/bin/env python3
import os
import sys
import argparse
import logging
from scapy.all import PcapReader, IP, Ether
from collections import defaultdict
from p4utils.mininetlib.network_API import NetworkAPI
import networkx as nx
from typing import Dict, Set, Tuple, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PcapTopologyMapper:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.flow_stats: Dict[Tuple[str, str], int] = defaultdict(int)
        self.node_connections: Dict[str, Set[str]] = defaultdict(set)
        self.ingress_nodes: Set[str] = set()
        self.egress_nodes: Set[str] = set()
        self.G = nx.Graph()

    def analyze_pcap(self) -> None:
        """Analyze PCAP file to extract flow statistics and node connections."""
        logger.info(f"Starting analysis of PCAP file: {self.pcap_file}")
        try:
            with PcapReader(self.pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    if IP in packet and Ether in packet:
                        src_mac = packet[Ether].src
                        dst_mac = packet[Ether].dst
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        # Track Layer 2 connections
                        self.node_connections[src_mac].add(dst_mac)
                        self.G.add_edge(src_mac, dst_mac)

                        # Track flow statistics
                        flow_key = (src_ip, dst_ip)
                        self.flow_stats[flow_key] += 1

                        # Identify potential ingress/egress nodes
                        self._update_edge_nodes(src_mac, dst_mac)
            logger.info("PCAP analysis completed successfully.")
        except FileNotFoundError:
            logger.error(f"PCAP file not found: {self.pcap_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error while analyzing PCAP: {e}")
            sys.exit(1)

    def _update_edge_nodes(self, src_mac: str, dst_mac: str) -> None:
        """Update ingress and egress node sets based on traffic patterns."""
        if not any(src_mac in conns for conns in self.node_connections.values()):
            self.ingress_nodes.add(src_mac)
            logger.debug(f"Identified ingress node: {src_mac}")
        if not self.node_connections[dst_mac]:
            self.egress_nodes.add(dst_mac)
            logger.debug(f"Identified egress node: {dst_mac}")

    def map_to_p4_topology(self, net: NetworkAPI, num_switches: int = 5) -> Dict[str, Any]:
        """Map the analyzed traffic to P4 switches in the topology."""
        topology_mapping = {
            'int_sources': [],
            'int_sinks': [],
            'flow_paths': defaultdict(list)
        }

        switches = [f"s{i}" for i in range(1, num_switches + 1)]
        logger.info(f"Available switches: {switches}")

        # Sort ingress nodes based on total flow counts
        sorted_ingress = sorted(
            self.ingress_nodes,
            key=lambda x: sum(
                count for (src, _), count in self.flow_stats.items() if src == x
            ),
            reverse=True
        )
        logger.debug(f"Sorted ingress nodes: {sorted_ingress}")

        # Select top ingress nodes as INT sources
        top_ingress = sorted_ingress[:2]
        for switch in switches:
            interfaces = net.get_switch_intfs(switch)
            if any(host in top_ingress for host in interfaces):
                topology_mapping['int_sources'].append(switch)
        logger.info(f"INT Source Switches: {topology_mapping['int_sources']}")

        # Sort egress nodes based on total flow counts
        sorted_egress = sorted(
            self.egress_nodes,
            key=lambda x: sum(
                count for (_, dst), count in self.flow_stats.items() if dst == x
            ),
            reverse=True
        )
        logger.debug(f"Sorted egress nodes: {sorted_egress}")

        # Select top egress nodes as INT sinks
        top_egress = sorted_egress[:2]
        for switch in switches:
            interfaces = net.get_switch_intfs(switch)
            if any(host in top_egress for host in interfaces):
                topology_mapping['int_sinks'].append(switch)
        logger.info(f"INT Sink Switches: {topology_mapping['int_sinks']}")

        # Optional: Map flow paths using networkx
        # This part can be expanded based on specific requirements
        # For example, finding shortest paths between ingress and egress nodes
        for (src_ip, dst_ip), count in self.flow_stats.items():
            # Placeholder for actual path mapping logic
            pass

        return topology_mapping

def configure_network(net: NetworkAPI, topology_mapping: Dict[str, List[str]]) -> None:
    """Configure the P4 network based on the topology mapping."""
    logger.info("Configuring INT source switches.")
    for source_switch in topology_mapping.get('int_sources', []):
        try:
            net.setP4SourceParams(
                source_switch,
                int_source=True,
                int_config={
                    'hop_metadata': True,
                    'flow_metadata': True,
                    'queue_metadata': True
                }
            )
            logger.debug(f"Configured INT source for switch: {source_switch}")
        except Exception as e:
            logger.error(f"Failed to configure INT source for {source_switch}: {e}")

    logger.info("Configuring INT sink switches.")
    for sink_switch in topology_mapping.get('int_sinks', []):
        try:
            net.setP4SinkParams(
                sink_switch,
                int_sink=True,
                collector_config={
                    'ip': '127.0.0.1',
                    'port': 54321,
                    'protocol': 'UDP'
                }
            )
            logger.debug(f"Configured INT sink for switch: {sink_switch}")
        except Exception as e:
            logger.error(f"Failed to configure INT sink for {sink_switch}: {e}")

def cleanup():
    """Clean up any running Mininet instances."""
    logger.info("Cleaning up Mininet instances.")
    try:
        os.system("sudo mn -c")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="PCAP Topology Mapper for P4App")
    parser.add_argument(
        "-p", "--pcap",
        required=True,
        help="Path to the PCAP file to analyze."
    )
    parser.add_argument(
        "-s", "--switches",
        type=int,
        default=5,
        help="Number of switches in the network topology (default: 5)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Initialize network
        cleanup()
        net = NetworkAPI()
        net.setLogLevel("info")

        # Create the original topology
        # TODO: Insert your existing topology creation code here
        # Example:
        # net.addHost('h1')
        # net.addSwitch('s1')
        # net.addLink('h1', 's1')
        # ...

        # Create and analyze topology mapping
        mapper = PcapTopologyMapper(args.pcap)
        mapper.analyze_pcap()

        # Map the analyzed traffic to P4 topology
        topology_mapping = mapper.map_to_p4_topology(net, num_switches=args.switches)

        # Configure the network with INT capabilities
        configure_network(net, topology_mapping)

        # Start the network
        logger.info("Starting the network.")
        net.startNetwork()

        # Print topology information
        logger.info("\nTopology Mapping Results:")
        logger.info(f"INT Source Switches: {topology_mapping.get('int_sources', [])}")
        logger.info(f"INT Sink Switches: {topology_mapping.get('int_sinks', [])}")
        net.printPortMapping()

        # Keep the script running to maintain the network
        logger.info("Network is up. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupt received. Shutting down the network.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        cleanup()
        sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    main()

