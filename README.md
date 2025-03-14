# PCAP-to-P4app

A tool for converting PCAP network captures to P4/Mininet network simulations for network experimentation and research.

## Description

PCAP-to-P4app analyzes network traffic captures (.pcap files) and generates a Mininet topology that accurately represents the network structure found in the traffic. Using advanced heuristics and fuzzy logic algorithms, it automatically:

- Identifies network subnets and distinguishes local vs. external traffic patterns
- Recognizes device roles (clients, servers, routers, gateways) based on behavioral analysis
- Maps out both physical (MAC-level) and logical (IP-level) network topology
- Infers subnet relationships and network hierarchy
- Generates a ready-to-run Mininet simulation that preserves the essential characteristics of the original network

This tool is particularly useful for network research, cybersecurity training, and test environment creation from real-world network captures.

## Installation

```bash
# Clone the repository
git clone https://github.com/trvon/pcap-to-p4app.git
cd pcap-to-p4app

# Build the application
make build
```

## Usage

```bash
# Basic usage with a single PCAP file
./build/pcap-to-p4app --pcap path/to/file.pcap

# Process a directory of PCAP files
./build/pcap-to-p4app --dir path/to/pcap/directory

# With all options
./build/pcap-to-p4app --pcap path/to/file.pcap --output topology.py --verbose

# Using make with a single file
make run-pcap PCAP=path/to/file.pcap

# Using make with a directory
make run-dir DIR=path/to/pcap/directory
```

## Command Line Options

- `--pcap`: Path to PCAP file to analyze (required if --dir is not used)
- `--dir`: Path to directory containing PCAP files (required if --pcap is not used)
- `--output`: Output file for Mininet topology (default: "mininet_topology.py")
- `--verbose`: Enable verbose output with analysis details

## Features

### Traffic Analysis
- Comprehensive MAC, IP, and port-level traffic analysis
- Protocol identification and classification (TCP, UDP, ICMP, ARP)
- Connection pattern analysis to identify relationships between hosts
- Traffic volume and frequency analysis for role determination
- Service port analysis for server role detection

### Network Structure Inference
- Automatic subnet detection and classification
- Gateway and router identification using traffic flow patterns
- Identification of internal vs. external communication
- Hierarchical network structure reconstruction
- Support for both IPv4 and IPv6 traffic analysis

### Topology Generation
- Mininet topology generation with proper network segmentation
- Subnet-aware switching infrastructure
- Preservation of critical network paths and relationships
- Generation of executable Python script for Mininet simulation
- Support for recreating complex multi-subnet architectures

### Batch Processing
- Process individual PCAP files or entire directories
- Combine multiple captures for comprehensive network analysis
- Automated handling of PCAP and PCAPNG file formats
- Verbose logging and analysis reporting

## How It Works

PCAP-to-P4app uses a multi-stage analysis pipeline to convert raw packet captures into meaningful network topologies:

1. **Packet Parsing**: Extracts MAC addresses, IP addresses, ports, and protocol information from the PCAP files
2. **Subnet Detection**: Analyzes IP address patterns to identify subnet structures
3. **Role Classification**: Uses fuzzy logic to determine the likely role of each device based on:
   - Connection patterns (client vs. server behavior)
   - Port usage (well-known service ports)
   - Traffic volume and direction
   - Position in the network hierarchy
4. **Topology Construction**: Builds a graph representation of the network with nodes and weighted edges
5. **Mininet Script Generation**: Converts the abstract topology into a concrete Mininet script

The fuzzy logic system assigns confidence scores to different potential roles for each device and selects the most likely role based on these scores.

## Examples

### Basic Network Analysis

```bash
# Analyze a single PCAP file and generate a Mininet topology
./build/pcap-to-p4app --pcap examples/home_network.pcap --verbose
```

This will produce detailed output about the detected subnets, node classifications, and generate a Mininet topology file.

### Advanced Usage

For more complex scenarios:

```bash
# Analyze multiple PCAP files from a directory 
# (useful for long-term or multi-point captures)
./build/pcap-to-p4app --dir captures/corporate_network/ --output corp_topology.py
```

## Development

### Building and Testing

Use the provided Makefile for common development tasks:

```
make        # Build with linting
make build  # Just build
make test   # Run tests
make fmt    # Format code
make lint   # Run linters
make clean  # Clean build artifacts
```

### Extending the Tool

The modular design allows for easy extension:
- Add new protocol handlers in the packet parsing phase
- Implement additional heuristics in the role classification system
- Create custom topology templates for different simulation environments

## License

See LICENSE file for details.

## Acknowledgments

This tool builds upon the excellent [gopacket](https://github.com/google/gopacket) library for packet parsing.
