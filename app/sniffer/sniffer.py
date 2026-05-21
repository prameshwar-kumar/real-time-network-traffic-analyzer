from scapy.all import sniff
from app.analyzer.traffic_analyzer import analyze_packet

def start_sniffing():
    sniff(prn=analyze_packet, store=False)