# TRex Traffic Generators

Collection of Python tools for generating network traffic using TRex.

## Overview

TRex is a powerful traffic generator used for testing network devices and measuring performance. This repository contains two types of traffic generators:

- **PCAP Replayer** - Replay real packets captured from the network
- **Synthetic Traffic Generator** - Create artificial traffic from scratch

Whether you need to replay actual captured traffic or generate specific protocol patterns for stress testing, these tools have you covered.

## Directory Structure

```
trex/
├── pcap_reader/           # PCAP replay tool
│   ├── pcap_generator.py  # Main script
│   ├── config.yaml        # Configuration
│   └── README.md          # Tool-specific documentation
└── traffic_generator/     # Synthetic traffic generators
    ├── dns_ipsec.py       # Main generator (DNS, TCP, UDP, IPSEC, FRAG)
    └── llm_refactor.py    # Alternative version
```

## Quick Start

### PCAP Replay

```bash
cd pcap_reader
python3 pcap_generator.py --config config.yaml
```

### Synthetic Traffic

```bash
cd traffic_generator
python3 dns_ipsec.py --config ../config.yaml
```

## Which Tool to Use?

| Feature | pcap_reader | traffic_generator |
|---------|-------------|-------------------|
| **Use case** | Replay real captured traffic | Generate synthetic patterns |
| **Protocols** | TCP, UDP, ICMP, RAW | TCP, UDP, DNS, IPSEC, FRAG |
| **IP variation** | Configurable IP ranges | Configurable IP ranges |
| **Port variation** | From pcap | Configurable ranges |
| **Learning curve** | Low | Medium |

**Use pcap_reader when:**
- You have a pcap file with real traffic you want to replay
- You need to test with actual application-level data
- You want to modify IP headers while keeping payload intact

**Use traffic_generator when:**
- You need to generate specific protocol patterns from scratch
- You want fine-grained control over every field (ports, flags, DNS queries)
- You're doing stress testing with high-volume synthetic traffic

## Requirements

- TRex server running
- Python 3
- PyYAML
- scapy
- TRex Python libraries (`trex_stl_lib`)

## Documentation

Each tool has its own README with detailed documentation:

- [PCAP Reader Documentation](./pcap_reader/README.md)

## Author

Maxim Barinov <maximbarinovdev@gmail.com>
