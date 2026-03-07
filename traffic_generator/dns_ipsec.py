#!/usr/bin/env python3
import sys
import argparse
import ipaddress
import datetime
import struct
import yaml

# --- Force TRex control-plane + TRex vendored scapy FIRST ---
TREX_CP = "/opt/trex/automation/trex_control_plane/interactive"
TREX_SCAPY = "/opt/trex/external_libs/scapy-2.4.3"

for p in (TREX_SCAPY, TREX_CP):
    if p not in sys.path:
        sys.path.insert(0, p)

from trex_stl_lib.api import (
    IP,
    TCP,
    UDP,
    Ether,
    Dot1Q,
    STLClient,
    STLError,
    STLPktBuilder,
    STLStream,
    STLTXCont,
)

# IMPORTANT: import Raw only AFTER TRex imports (so it binds to TRex scapy)
from scapy.packet import Raw


def _align_down_8(x: int) -> int:
    return (int(x) // 8) * 8


def _build_stl_pkt(pkt, vm=None):
    return STLPktBuilder(pkt=pkt, vm=vm) if vm else STLPktBuilder(pkt=pkt)


def get_network_bounds(ip_address_with_mask: str):
    try:
        network = ipaddress.ip_network(ip_address_with_mask, strict=False)
        return int(network.network_address), int(network.broadcast_address)
    except ValueError as e:
        print(f"Ошибка: {e}")
        return None, None


def dns_query_bytes(qname: str, qtype: str = "A", dns_id: int = 0x1234) -> bytes:
    """
    Делает минимальный DNS Query (RD=1, QDCOUNT=1) байтами.
    Без scapy DNS слоёв — меньше зависимостей и конфликтов.
    """
    qtype_map = {
        "A": 1,
        "AAAA": 28,
        "CNAME": 5,
        "TXT": 16,
        "MX": 15,
        "NS": 2,
        "SOA": 6,
        "SRV": 33,
        "PTR": 12,
    }
    qt = qtype_map.get(str(qtype).upper(), 1)

    if not qname.endswith("."):
        qname += "."

    # Header: id, flags(RD), qd, an, ns, ar
    hdr = struct.pack("!HHHHHH", dns_id & 0xFFFF, 0x0100, 1, 0, 0, 0)

    # QNAME
    q = b""
    for lab in qname.split("."):
        if not lab:
            continue
        b = lab.encode("ascii", "ignore")
        if len(b) > 63:
            b = b[:63]
        q += bytes([len(b)]) + b
    q += b"\x00"

    # QTYPE, QCLASS(IN=1)
    q += struct.pack("!HH", qt, 1)
    return hdr + q


def _build_esp_like_bytes(total_len: int, spi: int, seq: int, next_header: int = 59, icv_len: int = 12) -> bytes:
    """
    ESP-похоже: [SPI][SEQ] + data + pad + [padlen][nexthdr] + ICV(нули)
    """
    if total_len < 8:
        raise ValueError("ESP payload too small (<8). Increase packet_length_bytes.")

    hdr = struct.pack("!II", spi & 0xFFFFFFFF, seq & 0xFFFFFFFF)
    trailer_min = 2 + max(0, int(icv_len))
    room = total_len - len(hdr)

    if room < trailer_min:
        raise ValueError("packet_length_bytes too small for ESP trailer+ICV.")

    data_len = room - trailer_min
    data = b"\x42" * max(0, data_len)

    # минимальный padding “для вида”
    pad_len = 2 if data_len > 0 else 0
    padding = bytes((i % 256 for i in range(1, pad_len + 1)))
    trailer = struct.pack("!BB", pad_len & 0xFF, int(next_header) & 0xFF)
    icv = b"\x00" * max(0, int(icv_len))

    out = hdr + data + padding + trailer + icv

    if len(out) > total_len:
        out = out[:total_len]
    elif len(out) < total_len:
        out += b"\x00" * (total_len - len(out))
    return out


def create_packet_builder(
    packet_len: int,
    tcp_flags: str,
    src_ip_str: str,
    dst_ip_str: str,
    src_port_start: int,
    dst_port_start: int,
    protocol: str = "TCP",
    vm=None,
    src_mac=None,
    dst_mac=None,

    # VLAN
    vlan_id=None,

    # DNS extras
    dns_qname=None,
    dns_qtype="A",
    dns_id=0x1234,

    # IPSEC extras
    ipsec_mode="ESP",
    ipsec_spi=0x0badf00d,
    ipsec_seq=1,
    ipsec_next_header=59,
    ipsec_icv_len=12,

    # FRAG extras
    frag_mf=True,
):
    """
    Единственная функция построения пакетов для всех протоколов:
      TCP / UDP / DNS / IPSEC(ESP) / FRAG
    """

    base_ether = Ether()
    if src_mac:
        base_ether.src = src_mac
    if dst_mac:
        base_ether.dst = dst_mac

    if vlan_id is not None:
        base_ether = base_ether / Dot1Q(vlan=int(vlan_id))

    proto = str(protocol).upper().strip()

    # --- FRAG: Ether/IP/Raw (no L4) ---
    if proto == "FRAG":
        ip = IP(src=src_ip_str, dst=dst_ip_str)
        ip.flags = "MF" if frag_mf else 0
        ip.frag = 0
        headers = base_ether / ip

        payload_len = packet_len - len(headers)
        if payload_len < 0:
            raise ValueError(f"packet_length_bytes={packet_len} too small for Ether+IP({len(headers)})")
        pkt = headers / Raw(load=b"F" * payload_len)

        return _build_stl_pkt(pkt, vm)

    # --- IPSEC: Ether/IP(proto=50)/Raw ---
    if proto == "IPSEC":
        if str(ipsec_mode).upper() != "ESP":
            raise ValueError("Only IPSEC mode ESP is supported (proto=50).")

        ip = IP(src=src_ip_str, dst=dst_ip_str, proto=50)
        headers = base_ether / ip

        payload_len = packet_len - len(headers)
        if payload_len < 0:
            raise ValueError(f"packet_length_bytes={packet_len} too small for Ether+IP({len(headers)})")

        esp = _build_esp_like_bytes(
            total_len=payload_len,
            spi=int(ipsec_spi),
            seq=int(ipsec_seq),
            next_header=int(ipsec_next_header),
            icv_len=int(ipsec_icv_len),
        )

        pkt = headers / Raw(load=esp)
        return _build_stl_pkt(pkt, vm)

    # --- DNS: Ether/IP/UDP + DNS-bytes (no scapy DNS layer) ---
    if proto == "DNS":
        if not dns_qname:
            raise ValueError("protocol=DNS требует dns_qname (например example.com)")

        ip = IP(src=src_ip_str, dst=dst_ip_str)
        # UDP checksum в IPv4 может быть 0 (валидно). Так проще при VM-изменениях.
        udp = UDP(sport=src_port_start, dport=dst_port_start, chksum=0)

        dns_payload = dns_query_bytes(str(dns_qname), qtype=str(dns_qtype), dns_id=int(dns_id))
        headers = base_ether / ip / udp

        payload_len = packet_len - (len(headers) + len(dns_payload))
        if payload_len < 0:
            raise ValueError("packet_length_bytes too small for DNS payload. Increase packet_length_bytes.")

        pkt = headers / Raw(load=dns_payload + (b"\x00" * payload_len))
        return _build_stl_pkt(pkt, vm)

    # --- UDP / TCP ---
    ip = IP(src=src_ip_str, dst=dst_ip_str)

    if proto == "UDP":
        l4 = UDP(sport=src_port_start, dport=dst_port_start, chksum=0)
        headers = base_ether / ip / l4
    elif proto == "TCP":
        l4 = TCP(sport=src_port_start, dport=dst_port_start, flags=str(tcp_flags))
        headers = base_ether / ip / l4
    else:
        raise ValueError("Unsupported protocol. Use TCP/UDP/DNS/IPSEC/FRAG")

    payload_len = packet_len - len(headers)
    if payload_len < 0:
        raise ValueError(f"packet_length_bytes={packet_len} too small for headers({len(headers)})")

    pkt = headers / (b"a" * payload_len)
    return STLPktBuilder(pkt=pkt, vm=vm) if vm else STLPktBuilder(pkt=pkt)


def create_flow_variables(
    src_ip_min,
    src_ip_max,
    dst_ip_min,
    dst_ip_max,
    src_port_start,
    src_port_end,
    dst_port_start,
    dst_port_end,
    protocol,

    # FRAG options
    frag_offset_start_bytes=0,
    frag_offset_end_bytes=0,
    frag_offset_mode="random",
    ip_id_start=1,
    ip_id_end=65535,
    ip_id_mode="random",
    frag_mf=True,
):
    from trex_stl_lib.api import STLVmFixIpv4, STLVmFlowVar, STLVmWrFlowVar

    proto = str(protocol).upper().strip()
    vm = []

    # Source IP
    if src_ip_min is not None and src_ip_max is not None and src_ip_min != src_ip_max:
        vm += [
            STLVmFlowVar(name="src", min_value=src_ip_min, max_value=src_ip_max, size=4, op="inc"),
            STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),
        ]

    # Destination IP
    if dst_ip_min is not None and dst_ip_max is not None and dst_ip_min != dst_ip_max:
        vm += [
            STLVmFlowVar(name="dst", min_value=dst_ip_min, max_value=dst_ip_max, size=4, op="inc"),
            STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),
        ]

    # FRAG: write IP.id and flags+frag by absolute offsets (Ether=14 bytes)
    if proto == "FRAG":
        id_op = "random" if str(ip_id_mode).lower() == "random" else "inc"
        vm += [
            STLVmFlowVar(name="ip_id", min_value=int(ip_id_start), max_value=int(ip_id_end), size=2, op=id_op),
            STLVmWrFlowVar(fv_name="ip_id", pkt_offset=18),  # 14 + 4
        ]

        off0 = _align_down_8(int(frag_offset_start_bytes))
        off1 = _align_down_8(int(frag_offset_end_bytes))
        frag0 = max(0, min(8191, off0 // 8))
        frag1 = max(0, min(8191, off1 // 8))
        if frag0 > frag1:
            frag0, frag1 = frag1, frag0

        mf_bit = 0x2000 if frag_mf else 0x0000
        min_field = mf_bit | (frag0 & 0x1FFF)
        max_field = mf_bit | (frag1 & 0x1FFF)

        frag_op = "random" if str(frag_offset_mode).lower() == "random" else "inc"
        vm += [
            STLVmFlowVar(name="ip_frag_field", min_value=min_field, max_value=max_field, size=2, op=frag_op),
            STLVmWrFlowVar(fv_name="ip_frag_field", pkt_offset=20),  # 14 + 6
        ]

        vm += [STLVmFixIpv4(offset="IP")]
        return vm

    # Ports: UDP and DNS treat same
    if proto in ("UDP", "DNS"):
        if src_port_start != src_port_end:
            vm += [
                STLVmFlowVar(name="udp_sport", min_value=src_port_start, max_value=src_port_end, size=2, op="inc"),
                STLVmWrFlowVar(fv_name="udp_sport", pkt_offset="UDP.sport"),
            ]
        if dst_port_start != dst_port_end:
            vm += [
                STLVmFlowVar(name="udp_dport", min_value=dst_port_start, max_value=dst_port_end, size=2, op="inc"),
                STLVmWrFlowVar(fv_name="udp_dport", pkt_offset="UDP.dport"),
            ]

    elif proto == "TCP":
        if src_port_start != src_port_end:
            vm += [
                STLVmFlowVar(name="tcp_sport", min_value=src_port_start, max_value=src_port_end, size=2, op="inc"),
                STLVmWrFlowVar(fv_name="tcp_sport", pkt_offset="TCP.sport"),
            ]

    # IPSEC: no ports
    vm += [STLVmFixIpv4(offset="IP")]
    return vm


def main():
    parser = argparse.ArgumentParser(description="TRex traffic generator from YAML config.")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to YAML configuration file.")
    parser.add_argument("--server", type=str, help="TRex server (overrides config).")
    parser.add_argument("--port_tx", type=int, help="TRex TX port (overrides config).")
    parser.add_argument("--port_rx", type=int, help="TRex RX port (overrides config).")
    parser.add_argument("--duration", type=int, help="Duration seconds (overrides config).")
    parser.add_argument("--packet_len", type=int, help="Packet length bytes (overrides config).")
    args = parser.parse_args()

    # MACs

    #DST_MAC = "b8:3f:d2:1e:75:10" #HPE weak dosgate
    #DST_MAC = "10:70:fd:10:67:82" #.104 DG lab main connectx-5
    #DST_MAC = "9c:69:b4:66:4d:8c" #.104 DG Lab main intel
    DST_MAC_DEFAULT = "a0:88:c2:30:93:08" #.104 DG Lab main connectx-6
    SRC_MAC = "b8:3f:d2:9f:09:d2"

    c = None
    try:
        with open(args.config, "r") as f:
            config = yaml.safe_load(f)

        trex_server = args.server if args.server is not None else config.get("trex_server", "127.0.0.1")
        trex_port_tx = args.port_tx if args.port_tx is not None else config.get("trex_port_tx", 0)
        trex_port_rx = args.port_rx if args.port_rx is not None else config.get("trex_port_rx", 1)
        duration_seconds = args.duration if args.duration is not None else config.get("duration_seconds", 15)
        packet_length_bytes = args.packet_len if args.packet_len is not None else config.get("packet_length_bytes", 64)

        global_vlan_id = config.get("vlan_id")
        global_dst_mac = config.get("dst_mac", DST_MAC_DEFAULT)

        c = STLClient(server=trex_server)
        c.connect()
        c.reset()

        capture_info = False
        if config.get("save_pcap", False):
            c.set_service_mode(ports=[trex_port_tx], enabled=True)
            capture_info = c.start_capture(
                rx_ports=[trex_port_tx],
                limit=5000,
                mode="fixed",
                bpf_filter="tcp or udp or (ip proto 50) or (ip[6:2] & 0x3fff != 0)",
            )

        streams_to_add = []
        print("Configuring traffic streams from YAML:")

        for stream_cfg in config.get("traffic_streams", []):
            if not stream_cfg.get("enabled", True):
                print(f"  Skipping disabled stream: {stream_cfg.get('name', '<noname>')}")
                continue

            name = stream_cfg["name"]
            rate_pps = int(stream_cfg["rate_pps"])
            src_ip_str = stream_cfg["src_ip"]
            dst_ip_str = stream_cfg["dst_ip"]
            protocol = str(stream_cfg.get("protocol", "TCP"))
            proto_u = protocol.upper().strip()

            # Port defaults: for FRAG/IPSEC ports irrelevant -> 0
            if proto_u in ("FRAG", "IPSEC"):
                src_port_start = int(stream_cfg.get("src_port_start", 0))
                src_port_end = int(stream_cfg.get("src_port_end", src_port_start))
                dst_port_start = int(stream_cfg.get("dst_port_start", 0))
                dst_port_end = int(stream_cfg.get("dst_port_end", dst_port_start))
            else:
                src_port_start = int(stream_cfg.get("src_port_start", 1024))
                src_port_end = int(stream_cfg.get("src_port_end", src_port_start))
                dst_port_start = int(stream_cfg.get("dst_port_start", 0))
                dst_port_end = int(stream_cfg.get("dst_port_end", dst_port_start))

            tcp_flags = str(stream_cfg.get("tcp_flags", "S"))

            vlan_id = stream_cfg.get("vlan_id", global_vlan_id)
            dst_mac = stream_cfg.get("dst_mac", global_dst_mac)

            # DNS options
            dns_qname = stream_cfg.get("dns_qname")
            dns_qtype = stream_cfg.get("dns_qtype", "A")
            dns_id = int(stream_cfg.get("dns_id", 0x1234))

            # IPSEC options
            ipsec_mode = stream_cfg.get("ipsec_mode", "ESP")
            ipsec_spi = int(stream_cfg.get("ipsec_spi", 0x0badf00d))
            ipsec_seq = int(stream_cfg.get("ipsec_seq", 1))
            ipsec_next_header = int(stream_cfg.get("ipsec_next_header", 59))
            ipsec_icv_len = int(stream_cfg.get("ipsec_icv_len", 12))

            # FRAG options
            frag_offset_start = int(stream_cfg.get("frag_offset_start", 0))
            frag_offset_end = int(stream_cfg.get("frag_offset_end", frag_offset_start))
            frag_offset_mode = str(stream_cfg.get("frag_offset_mode", "random"))
            ip_id_start = int(stream_cfg.get("ip_id_start", 1))
            ip_id_end = int(stream_cfg.get("ip_id_end", 65535))
            ip_id_mode = str(stream_cfg.get("ip_id_mode", "random"))
            frag_mf = bool(stream_cfg.get("frag_mf", True))

            print(f"\n  Stream: {name} ({protocol} - {rate_pps} PPS)")
            if proto_u in ("TCP", "UDP", "DNS"):
                print(f"    Source: {src_ip_str}:{src_port_start}-{src_port_end}")
                print(f"    Destination: {dst_ip_str}:{dst_port_start}-{dst_port_end}")
            else:
                print(f"    Source: {src_ip_str}")
                print(f"    Destination: {dst_ip_str}")

            if proto_u == "TCP":
                print(f"    TCP Flags: {tcp_flags}")
            if proto_u == "DNS":
                print(f"    DNS: qname={dns_qname}, qtype={dns_qtype}")
            if proto_u == "IPSEC":
                print(f"    IPSEC(ESP): spi=0x{ipsec_spi:08x}, seq={ipsec_seq}, nexthdr={ipsec_next_header}, icv_len={ipsec_icv_len}")
            if proto_u == "FRAG":
                print(f"    FRAG: offset={frag_offset_start}-{frag_offset_end} ({frag_offset_mode}), ip_id={ip_id_start}-{ip_id_end} ({ip_id_mode}), MF={frag_mf}")

            if vlan_id is not None:
                print(f"    VLAN: {vlan_id}")
            if dst_mac != DST_MAC_DEFAULT:
                print(f"    DST_MAC: {dst_mac}")

            # Parse IP ranges
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

            vm = create_flow_variables(
                src_ip_min, src_ip_max,
                dst_ip_min, dst_ip_max,
                src_port_start, src_port_end,
                dst_port_start, dst_port_end,
                protocol,
                frag_offset_start_bytes=frag_offset_start,
                frag_offset_end_bytes=frag_offset_end,
                frag_offset_mode=frag_offset_mode,
                ip_id_start=ip_id_start,
                ip_id_end=ip_id_end,
                ip_id_mode=ip_id_mode,
                frag_mf=frag_mf,
            )

            pkt_builder = create_packet_builder(
                packet_length_bytes,
                tcp_flags,
                str(ipaddress.IPv4Address(src_ip_min)),
                str(ipaddress.IPv4Address(dst_ip_min)),
                src_port_start,
                dst_port_start,
                protocol,
                vm=vm,
                src_mac=SRC_MAC,
                dst_mac=dst_mac,
                vlan_id=vlan_id,
                dns_qname=dns_qname,
                dns_qtype=dns_qtype,
                dns_id=dns_id,
                ipsec_mode=ipsec_mode,
                ipsec_spi=ipsec_spi,
                ipsec_seq=ipsec_seq,
                ipsec_next_header=ipsec_next_header,
                ipsec_icv_len=ipsec_icv_len,
                frag_mf=frag_mf,
            )

            stream = STLStream(packet=pkt_builder, mode=STLTXCont(pps=rate_pps))
            streams_to_add.append(stream)

        if not streams_to_add:
            print("No active traffic streams.")
            return

        c.add_streams(streams_to_add, ports=[trex_port_tx])
        print(f"\nStarting traffic on port {trex_port_tx} for {duration_seconds} seconds...")
        c.start(ports=[trex_port_tx], duration=duration_seconds)
        c.wait_on_traffic()
        print("Traffic generation finished.")

        if config.get("save_pcap", False) and capture_info:
            dt = datetime.datetime.now().strftime("%Y-%d-%m_%H:%M:%S")
            pcap_path = f"/training/pcap/{dt}.pcap"
            c.stop_capture(capture_id=capture_info["id"], output=pcap_path)
            c.set_service_mode(ports=[trex_port_tx], enabled=False)

        stats = c.get_stats()
        print("\nTRex Port Stats:")
        print(f"Port {trex_port_tx} (TX):")
        print(f"  TX PPS: {stats[trex_port_tx]['opackets'] / duration_seconds:.2f}")
        print(f"  TX BPS: {stats[trex_port_tx]['obytes'] / duration_seconds * 8:.2f}")
        print(f"Port {trex_port_rx} (RX):")
        print(f"  RX PPS: {stats[trex_port_rx]['ipackets'] / duration_seconds:.2f}")
        print(f"  RX BPS: {stats[trex_port_rx]['ibytes'] / duration_seconds * 8:.2f}")

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
