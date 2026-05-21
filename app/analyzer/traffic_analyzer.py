from scapy.layers.inet import IP, TCP, UDP
from colorama import Fore, init
from datetime import datetime
from app.utils.helpers import log_packet

init(autoreset=True)

packet_count = 0
total_bytes = 0

# Common suspicious ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337]

# Protocol Mapping
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def analyze_packet(packet):
    global packet_count
    global total_bytes

    packet_count += 1
    total_bytes += len(packet)

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(Fore.CYAN + f"\nPacket #{packet_count}")

    # Check if packet has IP layer
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        protocol_num = packet[IP].proto
        protocol_name = PROTOCOLS.get(protocol_num, "OTHER")

        log_data = (
        f"[{current_time}] "
        f"{src_ip} -> {dst_ip} "
        f"{protocol_name}"
        )

        print(Fore.GREEN + f"Time           : {current_time}")
        print(Fore.GREEN + f"Source IP      : {src_ip}")
        print(Fore.GREEN + f"Destination IP : {dst_ip}")


        # TCP Analysis
        if packet.haslayer(TCP):
            print(Fore.YELLOW + "Protocol Type  : TCP")

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(Fore.YELLOW + f"Source Port    : {src_port}")
            print(Fore.YELLOW + f"Destination Port: {dst_port}")

            log_data += f" | {src_port} -> {dst_port}"

            # Suspicious Port Detection
            if dst_port in SUSPICIOUS_PORTS:

                alert_msg = (
                    f"ALERT! Suspicious Port Detected: {dst_port}"
                )

                print(Fore.RED + alert_msg)

                log_data += f" | ALERT: {dst_port}"


        # UDP Analysis
        elif packet.haslayer(UDP):
            print(Fore.MAGENTA + "Protocol Type  : UDP")

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(Fore.MAGENTA + f"Source Port    : {src_port}")
            print(Fore.MAGENTA + f"Destination Port: {dst_port}")

            log_data += f" | {src_port} -> {dst_port}"
        
        print(Fore.CYAN + f"Total Packets   : {packet_count}")
        print(Fore.CYAN + f"Total Bytes     : {total_bytes}")

        log_packet(log_data)

    else:
        print(Fore.RED + "Non-IP Packet Detected")