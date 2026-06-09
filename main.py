import argparse
import sys
import os

from sniffer.capture import PacketSniffer
from detectors.port_scan import PortScanDetector
from detectors.arp_spoof import ARPSpoofDetector
from detectors.ssh_bruteforce import SSHBruteForceDetector
from detectors.dns_anomaly import DNSAnomalyDetector


def build_sniffer(on_alert):
    sniffer = PacketSniffer(on_alert=on_alert)
    sniffer.register(PortScanDetector())
    sniffer.register(ARPSpoofDetector())
    sniffer.register(SSHBruteForceDetector())
    sniffer.register(DNSAnomalyDetector())
    return sniffer


def run_web():
    from web.app import run, emit_alert
    sniffer = build_sniffer(on_alert=emit_alert)
    print("[NetPulse] Web dashboard starting...")
    print("[NetPulse] Open http://192.168.0.111:5000 in your browser")
    run(sniffer)


def run_tui():
    import queue
    from tui.app import NetPulseTUI

    alert_queue = queue.Queue()
    sniffer = build_sniffer(on_alert=alert_queue.put)
    sniffer.start()
    app = NetPulseTUI(alert_queue=alert_queue)
    app.run()


def main():
    if os.geteuid() != 0:
        print("NetPulse requires root privileges for packet capture.")
        print("Run: sudo netpulse-env/bin/python3 main.py --mode [web|tui]")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="NetPulse — Network Intrusion Monitor")
    parser.add_argument(
        "--mode",
        choices=["web", "tui"],
        default="web",
        help="web = browser dashboard, tui = terminal UI",
    )
    args = parser.parse_args()

    if args.mode == "web":
        run_web()
    else:
        run_tui()


if __name__ == "__main__":
    main()