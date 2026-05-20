from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

print("Starting packet sniffing...")

sniff(prn=process_packet, store=False)