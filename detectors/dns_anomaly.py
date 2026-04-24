import time
import math
from collections import defaultdict
from typing import Optional
from utils.alert import Alert, Severity
import config


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


class DNSAnomalyDetector:
    name = "DNSAnomaly"

    def __init__(self):
        self._query_times = defaultdict(list)

    def analyze(self, packet) -> Optional[Alert]:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR

        if not (packet.haslayer(IP) and packet.haslayer(DNS)):
            return None

        dns = packet[DNS]

        if dns.qr != 0 or not dns.qd:
            return None

        src_ip = packet[IP].src
        qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
        now = time.time()

        self._query_times[src_ip] = [
            t for t in self._query_times[src_ip]
            if now - t < 60
        ]
        self._query_times[src_ip].append(now)

        if len(self._query_times[src_ip]) >= config.DNS_QUERY_THRESHOLD:
            return Alert(
                detector=self.name,
                severity=Severity.HIGH,
                src_ip=src_ip,
                message=f"High DNS query rate: {len(self._query_times[src_ip])} queries/min",
                extra={"query_count": len(self._query_times[src_ip]), "sample": qname}
            )

        parts = qname.split(".")
        if parts:
            subdomain = parts[0]
            ent = _entropy(subdomain)
            if len(subdomain) > config.DNS_LONG_SUBDOMAIN_LEN and ent > 3.5:
                return Alert(
                    detector=self.name,
                    severity=Severity.HIGH,
                    src_ip=src_ip,
                    message=f"Possible DNS tunneling: long high-entropy subdomain",
                    extra={"qname": qname, "length": len(subdomain), "entropy": round(ent, 2)}
                )

        for tld in config.DNS_SUSPICIOUS_TLDS:
            if qname.endswith(tld):
                return Alert(
                    detector=self.name,
                    severity=Severity.LOW,
                    src_ip=src_ip,
                    message=f"Query to suspicious TLD '{tld}': {qname}",
                    extra={"qname": qname, "tld": tld}
                )

        return None