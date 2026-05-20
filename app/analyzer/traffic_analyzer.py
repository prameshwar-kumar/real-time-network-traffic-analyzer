from scapy.layers.inet import IP, TCP, UDP
from colorama import Fore, init

init(autoreset=True)

packet_count = 0

def analyze_packet(packet):
    global packet_count

    packet_count += 1

    print(Fore.CYAN + f"\nPacket #{packet_count}")

    # Check if packet has IP layer
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(Fore.GREEN + f"Source IP      : {src_ip}")
        print(Fore.GREEN + f"Destination IP : {dst_ip}")
        print(Fore.GREEN + f"Protocol Number: {protocol}")

        # TCP Analysis
        if packet.haslayer(TCP):
            print(Fore.YELLOW + "Protocol Type  : TCP")

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(Fore.YELLOW + f"Source Port    : {src_port}")
            print(Fore.YELLOW + f"Destination Port: {dst_port}")

        # UDP Analysis
        elif packet.haslayer(UDP):
            print(Fore.MAGENTA + "Protocol Type  : UDP")

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(Fore.MAGENTA + f"Source Port    : {src_port}")
            print(Fore.MAGENTA + f"Destination Port: {dst_port}")

    else:
        print(Fore.RED + "Non-IP Packet Detected")