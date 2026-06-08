import threading
from typing import Callable
from utils.alert import Alert
from utils.logger import log_alert
import config


class PacketSniffer:

    def __init__(self, on_alert: Callable[[Alert], None]):
        self.on_alert = on_alert
        self.detectors = []
        self._thread = None
        self._running = False

    def register(self, detector):
        self.detectors.append(detector)

    def _process(self, packet):
        for detector in self.detectors:
            try:
                alert = detector.analyze(packet)
                if alert:
                    log_alert(alert)
                    self.on_alert(alert)
            except Exception:
                pass

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        from scapy.all import sniff
        sniff(
            iface=config.INTERFACE,
            prn=self._process,
            store=False,
            stop_filter=lambda _: not self._running
        )

    def stop(self):
        self._running = False