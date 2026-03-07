#!/usr/bin/env python3
#mbarinov engine power
#WLD for 11$ guys, need to buy it
import sys
import argparse
import ipaddress
import yaml

TREX_CP = "/opt/trex/automation/trex_control_plane/interactive"
TREX_SCAPY = "/opt/trex/external_libs/scapy-2.4.3"

for p in (TREX_SCAPY, TREX_CP):
    if p not in sys.path:
        sys.path.insert(0, p)

from trex_stl_lib.api import (
    IP,
    TCP,
    UDP,
    ICMP,
    Ether,
    Dot1Q,
    STLClient,
    STLError,
    STLPktBuilder,
    STLStream,
    STLTXCont,
)

from scapy.packet import Raw
from scapy.all import rdpcap
from scapy.layers.inet import ICMP as ScapyICMP


def get_network_bounds(ip_address_with_mask: str):
    try:
        network = ipaddress.ip_network(ip_address_with_mask, strict=False)
        return int(network.network_address), int(network.broadcast_address)
    except ValueError as e:
        print(f"Error: {e}")
        return None, None


def parse_pcap_files(pcap_files: list) -> list:
    packets = []
    for pcap_file in pcap_files:
        try:
            pkts = rdpcap(pcap_file)
            print(f"Loaded {len(pkts)} packets from {pcap_file}")
            packets.extend(pkts)
        except Exception as e:
            print(f"Warning: Could not load {pcap_file}: {e}")
    return packets


def extract_l4_payload(pkt):
    if not pkt.haslayer(IP):
        return None, None, None, None
    
    ip_layer = pkt[IP]
    ip_header_len = ip_layer.ihl * 4
    ip_total_len = ip_layer.len
    
    l4_payload: bytes = bytes(ip_layer.payload) if ip_layer.payload else b''
    l4_header: bytes = bytes(ip_layer)[ip_header_len:] if ip_layer else b''
    
    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        tcp_header_len = tcp_layer.dataofs * 4
        tcp_payload: bytes = bytes(tcp_layer.payload) if tcp_layer.payload else b''
        return 'TCP', l4_header[:tcp_header_len], tcp_payload, ip_total_len
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        udp_payload: bytes = bytes(udp_layer.payload) if udp_layer.payload else b''
        return 'UDP', l4_header[:8], udp_payload, ip_total_len
    elif pkt.haslayer(ScapyICMP):
        icmp_layer = pkt[ScapyICMP]
        icmp_payload: bytes = bytes(icmp_layer.payload) if icmp_layer.payload else b''
        return 'ICMP', l4_header, icmp_payload, ip_total_len
    else:
        return 'RAW', l4_header, l4_payload, ip_total_len


def create_flow_variables(src_ip_min, src_ip_max, dst_ip_min, dst_ip_max):
    from trex_stl_lib.api import STLVmFlowVar, STLVmWrFlowVar, STLVmFixIpv4

    vm = []

    if src_ip_min is not None and src_ip_max is not None and src_ip_min != src_ip_max:
        vm += [
            STLVmFlowVar(name="src", min_value=src_ip_min, max_value=src_ip_max, size=4, op="inc"),
            STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),
        ]

    if dst_ip_min is not None and dst_ip_max is not None and dst_ip_min != dst_ip_max:
        vm += [
            STLVmFlowVar(name="dst", min_value=dst_ip_min, max_value=dst_ip_max, size=4, op="inc"),
            STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),
        ]

    vm += [STLVmFixIpv4(offset="IP")]
    return vm


def process_packet(pkt, ignore_ipv4_header: bool, src_ip_str: str, dst_ip_str: str,
                  src_mac: str, dst_mac: str, vlan_id = None, use_vm: bool = True):
    
    if not pkt.haslayer(IP):
        return None
    
    ip_layer = pkt[IP]
    proto = ip_layer.proto
    
    l4_proto, l4_header, l4_payload, _ = extract_l4_payload(pkt)
    
    if l4_proto is None or l4_header is None:
        return None
    
    if l4_payload is None:
        l4_payload = b''
    
    base_ether = Ether()
    if src_mac:
        base_ether.src = src_mac
    if dst_mac:
        base_ether.dst = dst_mac
    
    if vlan_id is not None:
        base_ether = base_ether / Dot1Q(vlan=int(vlan_id))
    
    payload_len = len(l4_header) + len(l4_payload)
    
    if ignore_ipv4_header:
        new_ip = IP(bytes(ip_layer))
        new_ip.len = 20 + payload_len
        new_ip.chksum = 0
    else:
        if use_vm:
            new_ip = IP()
        else:
            new_ip = IP(src=src_ip_str, dst=dst_ip_str)
        new_ip.len = 20 + payload_len
        new_ip.chksum = 0
        new_ip.proto = proto
    
    if l4_proto == 'TCP':
        new_l4 = TCP(bytes(l4_header))
        new_l4.chksum = 0
    elif l4_proto == 'UDP':
        new_l4 = UDP(bytes(l4_header))
        new_l4.chksum = 0
    elif l4_proto == 'ICMP':
        new_l4 = ICMP(bytes(l4_header))
    else:
        new_l4 = bytes(l4_header)
    
    if l4_payload:
        if l4_proto in ('TCP', 'UDP'):
            pkt_final = base_ether / new_ip / new_l4 / Raw(load=l4_payload)
        elif l4_proto == 'ICMP':
            pkt_final = base_ether / new_ip / new_l4 / Raw(load=l4_payload)
        else:
            pkt_final = base_ether / new_ip / Raw(load=new_l4 + l4_payload)
    else:
        pkt_final = base_ether / new_ip / new_l4
    
    return pkt_final


def create_pcap_stream(packets: list, ignore_ipv4_header: bool, 
                       src_ip_str: str, dst_ip_str: str,
                       src_mac: str, dst_mac: str, vlan_id = None,
                       vm=None, use_vm: bool = True, group_by_protocol: bool = True):
    processed_packets = []
    protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'RAW': 0}
    skipped_count = 0
    
    for pkt in packets:
        processed = process_packet(
            pkt, ignore_ipv4_header, src_ip_str, dst_ip_str,
            src_mac, dst_mac, vlan_id, use_vm=use_vm
        )
        if processed:
            processed_packets.append(processed)
            if pkt.haslayer(TCP):
                protocol_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                protocol_counts['UDP'] += 1
            elif pkt.haslayer(ScapyICMP):
                protocol_counts['ICMP'] += 1
            else:
                protocol_counts['RAW'] += 1
        else:
            skipped_count += 1
    
    if not processed_packets:
        raise ValueError("No valid IPv4 packets found in pcap files")
    
    print(f"  Packets processed: {len(processed_packets)}")
    print(f"  Skipped (non-IPv4): {skipped_count}")
    print(f"  Protocol breakdown: {protocol_counts}")
    
    if group_by_protocol:
        return create_multi_protocol_streams(
            processed_packets, protocol_counts, vm
        )
    
    template_pkt = processed_packets[0]
    return STLPktBuilder(pkt=template_pkt, vm=vm)


def create_multi_protocol_streams(processed_packets: list, protocol_counts: dict, vm = None):
    from trex_stl_lib.api import STLPktBuilder
    
    protocol_packets = {'TCP': None, 'UDP': None, 'ICMP': None, 'RAW': None}
    
    for pkt in processed_packets:
        if pkt.haslayer(TCP) and protocol_packets['TCP'] is None:
            protocol_packets['TCP'] = pkt
        elif pkt.haslayer(UDP) and protocol_packets['UDP'] is None:
            protocol_packets['UDP'] = pkt
        elif pkt.haslayer(ICMP) and protocol_packets['ICMP'] is None:
            protocol_packets['ICMP'] = pkt
        elif protocol_packets['RAW'] is None:
            protocol_packets['RAW'] = pkt
    
    streams = []
    for proto, template_pkt in protocol_packets.items():
        if template_pkt is not None:
            pkt_builder = STLPktBuilder(pkt=template_pkt, vm=vm)
            streams.append((proto, pkt_builder))
    
    return streams


def main():
    parser = argparse.ArgumentParser(description="TRex PCAP replay traffic generator.")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to YAML configuration file.")
    parser.add_argument("--server", type=str, help="TRex server (overrides config).")
    parser.add_argument("--port_tx", type=int, help="TRex TX port (overrides config).")
    parser.add_argument("--port_rx", type=int, help="TRex RX port (overrides config).")
    parser.add_argument("--duration", type=int, help="Duration seconds (overrides config).")
    parser.add_argument("--rate-pps", type=int, help="Rate in PPS (overrides config).")
    args = parser.parse_args()

    DST_MAC_DEFAULT = "a0:88:c2:30:93:08"
    SRC_MAC_DEFAULT = "b8:3f:d2:9f:09:d2"

    c = None
    try:
        with open(args.config, "r") as f:
            config = yaml.safe_load(f)

        trex_server = args.server if args.server is not None else config.get("trex_server", "127.0.0.1")
        trex_port_tx = args.port_tx if args.port_tx is not None else config.get("trex_port_tx", 0)
        trex_port_rx = args.port_rx if args.port_rx is not None else config.get("trex_port_rx", 1)
        duration_seconds = args.duration if args.duration is not None else config.get("duration_seconds", 15)
        rate_pps = args.rate_pps if args.rate_pps is not None else config.get("rate_pps", 1000)

        pcap_files = config.get("pcap_files", [])
        if not pcap_files:
            raise ValueError("No pcap_files specified in config")

        ignore_ipv4_header = config.get("ignore_ipv4_header", False)
        src_ip_str = config.get("src_ip", "172.16.0.0/16")
        dst_ip_str = config.get("dst_ip", "10.22.0.1/32")

        global_vlan_id = config.get("vlan_id")
        global_dst_mac = config.get("dst_mac", DST_MAC_DEFAULT)
        global_src_mac = config.get("src_mac", SRC_MAC_DEFAULT)

        print(f"Loading packets from pcap files: {pcap_files}")
        packets = parse_pcap_files(pcap_files)
        print(f"Total packets loaded: {len(packets)}")

        src_net = ipaddress.ip_network(src_ip_str, strict=False)
        dst_net = ipaddress.ip_network(dst_ip_str, strict=False)

        if src_net.prefixlen == 32:
            src_ip_min = src_ip_max = int(src_net.network_address)
        else:
            src_ip_min, src_ip_max = get_network_bounds(src_ip_str)

        if dst_net.prefixlen == 32:
            dst_ip_min = dst_ip_max = int(dst_net.network_address)
        else:
            dst_ip_min, dst_ip_max = get_network_bounds(dst_ip_str)

        print(f"Source IP range: {src_ip_str} ({src_ip_min} - {src_ip_max})")
        print(f"Destination IP range: {dst_ip_str} ({dst_ip_min} - {dst_ip_max})")
        print(f"Ignore IPv4 header: {ignore_ipv4_header}")
        print(f"VLAN ID: {global_vlan_id}")
        print(f"Destination MAC: {global_dst_mac}")
        print(f"Rate: {rate_pps} PPS")
        print(f"Duration: {duration_seconds} seconds")

        if ignore_ipv4_header:
            print("\nNote: ignore_ipv4_header=true - copying IP from pcap, not using flow variables")
            vm = None
            use_vm = False
        else:
            print("\nUsing flow variables for IP range variation")
            vm = create_flow_variables(src_ip_min, src_ip_max, dst_ip_min, dst_ip_max)
            use_vm = True

        print("\nProcessing packets...")
        result = create_pcap_stream(
            packets,
            ignore_ipv4_header,
            str(ipaddress.IPv4Address(src_ip_min)),
            str(ipaddress.IPv4Address(dst_ip_min)),
            global_src_mac, global_dst_mac,
            global_vlan_id,
            vm=vm,
            use_vm=use_vm,
            group_by_protocol=True
        )

        if isinstance(result, list):
            print(f"\nCreating {len(result)} protocol streams...")
            num_streams = len(result)
            rate_per_stream = rate_pps // num_streams if num_streams > 0 else rate_pps
            streams_to_add = []
            for proto, pkt_builder in result:
                stream = STLStream(packet=pkt_builder, mode=STLTXCont(pps=rate_per_stream))
                streams_to_add.append(stream)
                print(f"  Created {proto} stream at {rate_per_stream} PPS")
        else:
            print("\nCreating single stream...")
            pkt_builder = result
            stream = STLStream(packet=pkt_builder, mode=STLTXCont(pps=rate_pps))
            streams_to_add = [stream]

        c = STLClient(server=trex_server)
        c.connect()
        c.reset()

        c.add_streams(streams_to_add, ports=[trex_port_tx])
        print(f"\nStarting traffic on port {trex_port_tx} for {duration_seconds} seconds at {rate_pps} PPS...")
        c.start(ports=[trex_port_tx], duration=duration_seconds)
        c.wait_on_traffic()
        print("Traffic generation finished.")

        stats = c.get_stats()
        print("\nTRex Port Stats:")
        print(f"Port {trex_port_tx} (TX):")
        tx_pps = stats[trex_port_tx]['opackets'] / duration_seconds if duration_seconds > 0 else 0
        tx_bps = stats[trex_port_tx]['obytes'] / duration_seconds * 8 if duration_seconds > 0 else 0
        print(f"  TX PPS: {tx_pps:.2f}")
        print(f"  TX BPS: {tx_bps:.2f}")
        print(f"Port {trex_port_rx} (RX):")
        rx_pps = stats[trex_port_rx]['ipackets'] / duration_seconds if duration_seconds > 0 else 0
        rx_bps = stats[trex_port_rx]['ibytes'] / duration_seconds * 8 if duration_seconds > 0 else 0
        print(f"  RX PPS: {rx_pps:.2f}")
        print(f"  RX BPS: {rx_bps:.2f}")

    except STLError as e:
        print(e)
    except FileNotFoundError:
        print(f"Error: Config file '{args.config}' not found.")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML config file: {e}")
    except ValueError as e:
        print(f"Configuration error: {e}")
    except ipaddress.AddressValueError as e:
        print(f"Invalid IP address or subnet in config: {e}")
    except ipaddress.NetmaskValueError as e:
        print(f"Invalid netmask in subnet in config: {e}")
    finally:
        if c and c.is_connected():
            c.disconnect()


if __name__ == "__main__":
    main()
