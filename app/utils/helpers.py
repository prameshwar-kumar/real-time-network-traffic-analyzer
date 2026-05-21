from datetime import datetime
import os
LOG_FILE = "logs/traffic_logs.txt"

def log_packet(data):
    os.makedirs("logs",exist_ok=True)

    with open(LOG_FILE, "a") as file:
        file.write(data + "\n")

