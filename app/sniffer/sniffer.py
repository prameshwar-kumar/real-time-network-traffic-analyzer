from scapy.all import sniff
from app.analyzer.traffic_analyzer import analyze_packet

print("Starting real time Traffic Analyzer\n")
sniff(prn=analyze_packet, store=False)
