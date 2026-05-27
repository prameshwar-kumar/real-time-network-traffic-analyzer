from collections import deque
from collections import defaultdict

metrics = {
    "packet_count": 0,
    "total_bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
}

# time series data (last 60 seconds)
packet_history = deque(maxlen=60)
byte_history = deque(maxlen=60)

top_ips = defaultdict(int)