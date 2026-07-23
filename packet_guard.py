import argparse
import csv
from datetime import datetime
from pathlib import Path

from scapy.all import IP, IPv6, ICMP, TCP, UDP, sniff, wrpcap

FIELDNAMES = ["timestamp", "source", "destination", "protocol", "length"]


class PacketGuard:
    def __init__(self, log_path, pcap_path, report_path):
        self.log_path = Path(log_path)
        self.pcap_path = Path(pcap_path)
        self.report_path = Path(report_path)
        self._prepare_directories()
        self._initialize_log()

    def _prepare_directories(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.parent.mkdir(parents=True, exist_ok=True)

    def _initialize_log(self):
        if not self.log_path.exists():
            with self.log_path.open(mode="w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
                writer.writeheader()

    def _packet_to_record(self, packet):
        source = destination = "-"
        protocol_name = packet.name

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            source = ip_layer.src
            destination = ip_layer.dst
            protocol_name = self._protocol_name(ip_layer.proto)
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            source = ip_layer.src
            destination = ip_layer.dst
            protocol_name = self._protocol_name(ip_layer.nh)

        return {
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "source": source,
            "destination": destination,
            "protocol": protocol_name,
            "length": len(packet),
        }

    @staticmethod
    def _protocol_name(number):
        if number == 6:
            return "TCP"
        if number == 17:
            return "UDP"
        if number == 1:
            return "ICMP"
        return str(number)

    def process_packet(self, packet):
        record = self._packet_to_record(packet)
        with self.log_path.open(mode="a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writerow(record)
        return record

    def start_capture(self, interface, duration):
        print(f"Capturing traffic on {interface} for {duration} seconds...")
        packets = sniff(iface=interface, timeout=duration, prn=self.process_packet, store=True)
        print(f"Capture complete: {len(packets)} packets recorded.")

        if packets:
            wrpcap(self.pcap_path, packets)
            print(f"Saved packet capture to: {self.pcap_path}")

        return packets

    def load_log(self):
        with self.log_path.open(mode="r", newline="") as file:
            return list(csv.DictReader(file))

    def is_suspicious(self, record):
        length = int(record.get("length", 0))
        protocol = record.get("protocol", "")
        source = record.get("source", "")
        destination = record.get("destination", "")

        if protocol == "UDP" and length > 500:
            return True
        if protocol not in {"TCP", "UDP", "ICMP"} and length > 128:
            return True
        if destination == "255.255.255.255" or destination.startswith("224."):
            return True
        if length > 1200:
            return True
        return False

    def generate_report(self):
        records = self.load_log()
        suspicious = [record for record in records if self.is_suspicious(record)]

        with self.report_path.open(mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(suspicious)

        print("Suspicious activity analysis complete.")
        print(f"Total records analyzed: {len(records)}")
        print(f"Suspicious entries found: {len(suspicious)}")
        if suspicious:
            print(f"Report written to: {self.report_path}")
        else:
            print("No suspicious activity detected.")

        return suspicious


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PacketGuard: capture network traffic, log packet metadata, and generate suspicious activity reports."
    )
    parser.add_argument("-i", "--interface", default=None, help="Network interface to capture from")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Capture duration in seconds")
    parser.add_argument("--log", default="logs/traffic_log.csv", help="CSV path for packet logs")
    parser.add_argument("--pcap", default="captures/test.pcap", help="PCAP output file path")
    parser.add_argument("--report", default="reports/suspicious_report.csv", help="Suspicious activity report path")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.interface:
        raise SystemExit("Error: please provide an interface with --interface or -i.")

    guard = PacketGuard(log_path=args.log, pcap_path=args.pcap, report_path=args.report)
    guard.start_capture(interface=args.interface, duration=args.duration)
    guard.generate_report()


if __name__ == "__main__":
    main()
    
