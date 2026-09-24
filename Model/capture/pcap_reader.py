import os
from scapy.all import PcapReader, IP, TCP, UDP, ICMP

def parse_packets(pcap_path, max_packets=None):
    """
    Iteratively reads a PCAP file using Scapy's PcapReader.
    Extracts IP packets and normalizes them into a structured format.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packet_count = 0
    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if not pkt.haslayer(IP):
                continue
            
            ip_layer = pkt[IP]
            
            # Basic packet details
            timestamp = float(pkt.time)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "OTHER"
            size = len(pkt)
            
            src_port = None
            dst_port = None
            syn = 0
            ack = 0
            rst = 0
            fin = 0
            psh = 0
            urg = 0
            payload_size = 0
            
            # Layer 4 Parsing
            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                flags = pkt[TCP].flags
                # Parse TCP flags individually
                syn = 1 if flags & 0x02 else 0
                ack = 1 if flags & 0x10 else 0
                rst = 1 if flags & 0x04 else 0
                fin = 1 if flags & 0x01 else 0
                psh = 1 if flags & 0x08 else 0
                urg = 1 if flags & 0x20 else 0
                if pkt[TCP].payload:
                    payload_size = len(pkt[TCP].payload)
                
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                if pkt[UDP].payload:
                    payload_size = len(pkt[UDP].payload)
                
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                # ICMP does not have source/destination port concepts in standard ip 5-tuples
                
            else:
                # Attempt to extract ports if present dynamically, or retain None
                # Map known protocols by protocol numbers if needed
                proto_num = ip_layer.proto
                if proto_num == 1: protocol = "ICMP"
                elif proto_num == 6: protocol = "TCP"
                elif proto_num == 17: protocol = "UDP"
                else:
                    protocol = f"PROTO_{proto_num}"

            yield {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "size": size,
                "payload_size": payload_size,
                "syn": syn,
                "ack": ack,
                "rst": rst,
                "fin": fin,
                "psh": psh,
                "urg": urg
            }
            
            packet_count += 1
            if max_packets and packet_count >= max_packets:
                break
