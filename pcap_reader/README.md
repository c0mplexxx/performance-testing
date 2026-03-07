# PCAP Generator for TRex

Traffic generator that replays packets from pcap/pcapng files with customizable L2/L3 headers.

## Overview

This tool reads packets from pcap files and replays them through TRex with the ability to:

- Customize IP header (src/dst IPs from config)
- Copy IP header from pcap as-is
- Keep L4 header and payload from pcap
- Set custom VLAN and MAC addresses from config
- Create separate streams per protocol (TCP/UDP/ICMP/Raw)

## Requirements

- TRex server running
- Python 3
- PyYAML
- scapy
- TRex Python libraries (trex_stl_lib)

## Usage

```bash
# Basic usage
python pcap_generator.py --config config.yaml

# Override TRex server
python pcap_generator.py --config config.yaml --server 192.168.1.100

# Override rate
python pcap_generator.py --config config.yaml --rate-pps 500000

# Override duration
python pcap_generator.py --config config.yaml --duration 60
```

## Configuration

### config.yaml Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pcap_files` | list | [] | **Required.** List of pcap/pcapng file paths |
| `ignore_ipv4_header` | bool | false | **false:** use src_ip/dst_ip from config. **true:** copy IP from pcap |
| `src_ip` | string | "172.16.0.0/16" | Source IP prefix in CIDR notation (used when ignore_ipv4_header: false) |
| `dst_ip` | string | "10.22.0.1/32" | Destination IP prefix in CIDR notation (used when ignore_ipv4_header: false) |
| `rate_pps` | int | 1000 | Total packets per second for all traffic (shared across protocol streams) |
| `vlan_id` | int | - | VLAN tag (optional) |
| `dst_mac` | string | "a0:88:c2:30:93:08" | Destination MAC address |

### TRex Standard Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `trex_server` | string | "127.0.0.1" | TRex server address |
| `trex_port_tx` | int | 0 | TX port |
| `trex_port_rx` | int | 1 | RX port |
| `duration_seconds` | int | 15 | Duration in seconds |

## How It Works

### Packet Processing Flow

1. **Load packets** from all pcap_files using scapy `rdpcap`
2. **For each IPv4 packet:**
   - Strip original Ethernet header (always)
   - **If `ignore_ipv4_header: false`:**
     - Build new IP header from config (src_ip/dst_ip)
     - Use flow_vars for IP range variation
   - **If `ignore_ipv4_header: true`:**
     - Copy IP header from pcap
     - Recalculate IP total_length to match new payload
   - Copy L4 header (TCP/UDP/ICMP) from pcap as-is
   - Copy L4 payload from pcap as-is
   - Add new Ether + VLAN from config
3. **Create streams** - one per protocol type found in pcap
4. **Replay at configured rate_pps** - rate is shared across all streams

### IP Header Length Handling

If pcap has IP header with options (e.g., 28 bytes) but custom template is 20 bytes:
- IP total_length is recalculated automatically
- Checksum set to 0 (valid for IPv4 per RFC)

### VLAN and MAC

- **Original Ethernet header from pcap is ALWAYS stripped**
- New MAC from config (`dst_mac`)
- New VLAN from config (`vlan_id`)

### Multi-Protocol Support

When pcap contains multiple protocol types (TCP, UDP, ICMP), the tool automatically creates separate streams for each protocol. Each stream uses the first packet of that protocol type as its template.

## Limitations

1. **IP Options Lost:** When `ignore_ipv4_header: false`, IP header options from pcap are stripped (standard 20-byte header used)
2. **Single Template Per Protocol:** Only first packet of each protocol type is used as template - other packets of same protocol are not replayed
3. **Rate Sharing:** `rate_pps` is shared across all protocol streams (each gets equal share)

## Examples

### Example 1: Replay with custom IPs

```yaml
pcap_files:
  - "/tmp/capture.pcap"
ignore_ipv4_header: false
src_ip: "172.16.0.0/16"
dst_ip: "10.22.0.1/32"
rate_pps: 1000000
vlan_id: 110
dst_mac: "a0:88:c2:30:93:08"
```

### Example 2: Replay with original IPs from pcap

```yaml
pcap_files:
  - "/tmp/capture.pcap"
ignore_ipv4_header: true
rate_pps: 500000
vlan_id: 100
dst_mac: "a0:88:c2:30:93:08"
```

### Example 3: Multiple pcap files

```yaml
pcap_files:
  - "/tmp/capture1.pcap"
  - "/tmp/capture2.pcapng"
  - "/tmp/capture3.pcap"
ignore_ipv4_header: false
src_ip: "192.168.0.0/24"
dst_ip: "10.10.14.0/24"
rate_pps: 2500000
vlan_id: 200
dst_mac: "a0:88:c2:30:93:08"
```

## Performance Notes

- **Max streams per port:** ~20,000 (TRex limit)
- **This tool creates:** Up to 4 streams (TCP, UDP, ICMP, RAW) per run
- **With 64 cores:** Can handle 10+ MPPS easily
- **PPS limit:** Depends on NIC, packet size, and CPU cores

## Files

| File | Description |
|------|-------------|
| `pcap_generator.py` | Main script |
| `dns_ipsec.py` | Original generator for synthetic traffic |
| `config.yaml` | Configuration file |
| `README.md` | This documentation |
