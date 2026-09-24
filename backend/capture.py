from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime

packets_data = []


def packet_callback(packet):

    # We only process packets that contain IP information
    if IP not in packet:
        return

    data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "packet_size": len(packet)
    }

    # TCP packet
    if TCP in packet:
        data["protocol"] = "TCP"
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport

    # UDP packet
    elif UDP in packet:
        data["protocol"] = "UDP"
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    packets_data.append(data)

    print(data)


print("Starting packet capture...")
print("Capturing 50 IP packets...\n")

sniff(
    prn=packet_callback,
    count=50
)

# Save captured data
with open("traffic.json", "w") as file:
    json.dump(packets_data, file, indent=4)

print("\nCapture finished.")
print(f"Saved {len(packets_data)} packets to traffic.json")