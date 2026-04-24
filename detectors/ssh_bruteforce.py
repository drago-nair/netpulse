import re
import time
import threading
from collections import defaultdict
from typing import Optional
from utils.alert import Alert, Severity
import config

_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)"
)


class SSHBruteForceDetector:
    name = "SSHBruteForce"

    def __init__(self):
        self._failures = defaultdict(list)
        self._alerted = set()
        self._lock = threading.Lock()
        self._running = True
        self._pending_alerts = []

        self._thread = threading.Thread(target=self._watch_log, daemon=True)
        self._thread.start()

    def _watch_log(self):
        try:
            with open(config.SSH_LOG_PATH, "r") as f:
                f.seek(0, 2)
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    self._parse_line(line.strip())
        except (FileNotFoundError, PermissionError):
            pass

    def _parse_line(self, line: str):
        match = _FAILED_RE.search(line)
        if not match:
            return

        username = match.group(1)
        src_ip = match.group(2)
        now = time.time()

        with self._lock:
            self._failures[src_ip] = [
                t for t in self._failures[src_ip]
                if now - t < config.SSH_ATTEMPT_WINDOW
            ]
            self._failures[src_ip].append(now)
            count = len(self._failures[src_ip])

            if count >= config.SSH_ATTEMPT_THRESHOLD and src_ip not in self._alerted:
                self._alerted.add(src_ip)
                self._pending_alerts.append(
                    Alert(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        src_ip=src_ip,
                        message=f"SSH brute force: {count} failed attempts in {config.SSH_ATTEMPT_WINDOW}s (user: {username})",
                        extra={"attempts": count, "username": username}
                    )
                )

    def analyze(self, packet) -> Optional[Alert]:
        with self._lock:
            if self._pending_alerts:
                return self._pending_alerts.pop(0)

        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            return None

        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None

        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.dport == config.SSH_PORT and tcp.flags == 0x02:
            src = ip.src
            now = time.time()

            with self._lock:
                self._failures[src] = [
                    t for t in self._failures[src]
                    if now - t < config.SSH_ATTEMPT_WINDOW
                ]
                self._failures[src].append(now)
                count = len(self._failures[src])

                if count >= config.SSH_ATTEMPT_THRESHOLD and src not in self._alerted:
                    self._alerted.add(src)
                    return Alert(
                        detector=self.name,
                        severity=Severity.HIGH,
                        src_ip=src,
                        message=f"SSH rapid connections: {count} SYNs to port {config.SSH_PORT} in {config.SSH_ATTEMPT_WINDOW}s",
                        extra={"syn_count": count}
                    )

        return None

    def stop(self):
        self._running = False