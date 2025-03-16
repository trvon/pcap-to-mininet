# pcap-to-mininet

An experimental tool for converting PCAP network captures to mininet network topologies for network experimentation and research.

## Description

PCAP-to-P4app analyzes network traffic captures (.pcap files) and generates a Mininet topology that accurately represents the network structure found in the traffic. Using advanced heuristics and fuzzy logic algorithms, it automatically:

- Identifies network subnets and distinguishes local vs. external traffic patterns
- Recognizes device roles (clients, servers, routers, gateways) based on behavioral analysis
- Maps out both physical (MAC-level) and logical (IP-level) network topology
- Infers subnet relationships and network hierarchy
- Generates a ready-to-run Mininet simulation that preserves the essential characteristics of the original network
- Creates visualizations of the detected network topology for better understanding

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

# Generate visualization
./build/pcap-to-p4app --pcap path/to/file.pcap --visualize

# Using make with a single file
make run-pcap PCAP=path/to/file.pcap

# Using make with a directory
make run-dir DIR=path/to/pcap/directory

# Generate visualization using make
make viz-pcap PCAP=path/to/file.pcap
```

## Command Line Options

- `--pcap`: Path to PCAP file to analyze (required if --dir is not used)
- `--dir`: Path to directory containing PCAP files (required if --pcap is not used)
- `--output`: Output file for Mininet topology (default: "mininet_topology.py")
- `--visualize`: Generate visual representation of the network topology (default: true)
- `--viz-output`: Output file for visualization (default: derived from output file name)
- `--verbose`: Enable verbose output with analysis details

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
6. **Visualization Generation**: Creates a GraphViz DOT file to visualize the network topology

The fuzzy logic system assigns confidence scores to different potential roles for each device and selects the most likely role based on these scores.

## Examples

### Basic Network Analysis

```bash
# Analyze a single PCAP file and generate a Mininet topology
./build/pcap-to-p4app --pcap examples/home_network.pcap --verbose
```

This will produce detailed output about the detected subnets, node classifications, and generate a Mininet topology file.

### Topology Visualization

```bash
# Generate a visualization of the network topology
./build/pcap-to-p4app --pcap examples/home_network.pcap --visualize

# Using make (automatically converts to PNG if Graphviz is installed)
make viz-pcap PCAP=examples/home_network.pcap
```

This will create:
1. A DOT file that represents the network topology
2. If Graphviz is installed, a PNG image showing the network structure with:
   - Color-coded nodes based on device roles
   - Subnets grouped together in clusters
   - Edge thickness representing connection strength
   - Detailed node information (IP, MAC, role)

### Advanced Usage

For more complex scenarios:

```bash
# Analyze multiple PCAP files from a directory 
# (useful for long-term or multi-point captures)
./build/pcap-to-p4app --dir captures/corporate_network/ --output corp_topology.py
```

## License

See LICENSE file for details.

## Acknowledgments

This tool builds upon the excellent [gopacket](https://github.com/google/gopacket) library for packet parsing.
