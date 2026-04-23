from typing import Optional
from utils.alert import Alert, Severity


class ARPSpoofDetector:
    name = "ARPSpoof"

    def __init__(self):
        self._arp_table = {}

    def analyze(self, packet) -> Optional[Alert]:
        from scapy.layers.l2 import ARP

        if not packet.haslayer(ARP):
            return None

        arp = packet.getlayer(ARP)

        if arp.op != 2:
            return None

        src_ip = arp.psrc
        src_mac = arp.hwsrc

        if not src_ip or src_ip == "0.0.0.0":
            return None

        if src_ip in self._arp_table:
            known_mac = self._arp_table[src_ip]
            if known_mac.lower() != src_mac.lower():
                return Alert(
                    detector=self.name,
                    severity=Severity.CRITICAL,
                    src_ip=src_ip,
                    message=f"ARP spoofing detected! IP {src_ip} changed MAC: {known_mac} → {src_mac}",
                    extra={
                        "ip": src_ip,
                        "known_mac": known_mac,
                        "new_mac": src_mac
                    }
                )
        else:
            self._arp_table[src_ip] = src_mac

        return None