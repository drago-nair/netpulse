import time
from collections import defaultdict
from typing import Optional
from utils.alert import Alert, Severity
import config


class PortScanDetector:
    name = "PortScan"

    def __init__(self):
        self._activity = defaultdict(list)
        self._alerted = set()

    def analyze(self, packet) -> Optional[Alert]:
        from scapy.layers.inet import IP, TCP

        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None

        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.flags != 0x02:
            return None

        src = ip.src
        dst_port = tcp.dport
        now = time.time()

        self._activity[src] = [
            (t, p) for t, p in self._activity[src]
            if now - t < config.PORT_SCAN_WINDOW
        ]

        self._activity[src].append((now, dst_port))

        unique_ports = {p for _, p in self._activity[src]}

        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD and src not in self._alerted:
            self._alerted.add(src)
            return Alert(
                detector=self.name,
                severity=Severity.HIGH,
                src_ip=src,
                dst_ip=ip.dst,
                message=f"Port scan detected: {len(unique_ports)} unique ports in {config.PORT_SCAN_WINDOW}s",
                extra={"ports_seen": sorted(unique_ports)[:10]}
            )

        if len(unique_ports) < config.PORT_SCAN_THRESHOLD // 2:
            self._alerted.discard(src)

        return None