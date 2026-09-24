import time
import math
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

class FlowTracker:
    def __init__(self):
        self.flows = {}  # key: (src_ip, dst_ip, src_port, dst_port, proto)
        self.global_src_ips = set()
        self.global_dst_ips = set()
        self.global_src_ports = set()
        self.global_dst_ports = set()
        self.start_time = time.time()
        self.connection_count = 0
        self.lock = threading.Lock()

    def process_packet(self, packet):
        if not IP in packet:
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        proto = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")
        
        src_port = 0
        dst_port = 0
        flags = ""
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        
        with self.lock:
            self.global_src_ips.add(src_ip)
            self.global_dst_ips.add(dst_ip)
            self.global_src_ports.add(src_port)
            self.global_dst_ports.add(dst_port)
            
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    "start_time": time.time(),
                    "last_time": time.time(),
                    "packet_count": 0,
                    "byte_count": 0,
                    "sq_byte_count": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                    "fin_count": 0,
                }
                self.connection_count += 1
                
            flow = self.flows[flow_key]
            flow["last_time"] = time.time()
            flow["packet_count"] += 1
            flow["byte_count"] += size
            flow["sq_byte_count"] += size * size
            
            flags_str = str(flags)
            if 'S' in flags_str: flow["syn_count"] += 1
            if 'A' in flags_str: flow["ack_count"] += 1
            if 'R' in flags_str: flow["rst_count"] += 1
            if 'F' in flags_str: flow["fin_count"] += 1

    def get_features_and_clear(self):
        with self.lock:
            current_time = time.time()
            global_duration = max(0.1, current_time - self.start_time)
            
            features_list = []
            
            for key, flow in self.flows.items():
                src_ip, dst_ip, src_port, dst_port, proto = key
                duration = max(0.1, flow["last_time"] - flow["start_time"])
                
                pkts = flow["packet_count"]
                bytes_tot = flow["byte_count"]
                
                rate = pkts / duration
                sbytes = bytes_tot / duration
                smean = bytes_tot / pkts if pkts > 0 else 0
                
                # std dev of packet size
                variance = (flow["sq_byte_count"] / pkts) - (smean * smean) if pkts > 0 else 0
                stcpb = math.sqrt(variance) if variance > 0 else 0
                
                features = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "packets_per_second": rate,
                    "bytes_per_second": sbytes,
                    "mean_packet_size": smean,
                    "std_packet_size": stcpb,
                    "syn_ratio": flow["syn_count"] / pkts if pkts > 0 else 0,
                    "ack_ratio": flow["ack_count"] / pkts if pkts > 0 else 0,
                    "rst_ratio": flow["rst_count"] / pkts if pkts > 0 else 0,
                    "fin_ratio": flow["fin_count"] / pkts if pkts > 0 else 0,
                    "unique_src_ips": len(self.global_src_ips),
                    "unique_dst_ips": len(self.global_dst_ips),
                    "unique_src_ports": len(self.global_src_ports),
                    "unique_dst_ports": len(self.global_dst_ports),
                    "connection_rate": self.connection_count / global_duration,
                    "session_duration": duration
                }
                features_list.append(features)
                
            # Reset trackers for next window
            self.flows.clear()
            self.global_src_ips.clear()
            self.global_dst_ips.clear()
            self.global_src_ports.clear()
            self.global_dst_ports.clear()
            self.start_time = time.time()
            self.connection_count = 0
            
            return features_list

tracker = FlowTracker()

def start_sniffing():
    print("🚀 Starting live packet capture...")
    try:
        sniff(prn=tracker.process_packet, store=False)
    except PermissionError:
        print("⚠️ Permission denied for raw socket. You must run this script with sudo (sudo python api.py) to enable LIVE sniffing.")
    except Exception as e:
        print(f"⚠️ Live sniffing failed: {e}")

threading.Thread(target=start_sniffing, daemon=True).start()
