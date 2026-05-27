from scapy.layers.inet import IP, TCP, UDP
import app.dashboard.metrics as m

def analyze_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        m.top_ips[src_ip] += 1

        m.metrics["packet_count"] += 1
        m.metrics["total_bytes"] += len(packet)

        if packet.haslayer(TCP):
            m.metrics["tcp"] += 1

        elif packet.haslayer(UDP):
            m.metrics["udp"] += 1

        else:
            m.metrics["icmp"] += 1