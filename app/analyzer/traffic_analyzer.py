from scapy.layers.inet import IP, TCP, UDP
import time
import app.dashboard.metrics as m

def analyze_packet(packet):

    if packet.haslayer(IP):

        m.metrics["packet_count"] += 1
        m.metrics["total_bytes"] += len(packet)

        if packet.haslayer(TCP):
            m.metrics["tcp"] += 1

        elif packet.haslayer(UDP):
            m.metrics["udp"] += 1

        else:
            m.metrics["icmp"] += 1