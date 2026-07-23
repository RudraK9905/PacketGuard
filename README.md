# PacketGuard

PacketGuard is a lightweight Python packet capture and traffic analysis tool designed for learning and portfolio demonstration. It captures network traffic from a specified interface, logs metadata for each packet, saves packet captures in PCAP format, and generates a suspicious activity report based on simple detection rules.

## Why PacketGuard

This project is intended to show:

- practical use of packet capture with `scapy`
- structured logging of packet metadata to CSV
- export of captures to PCAP for further analysis
- basic suspicious traffic detection and reporting
- a clear command-line interface for configurable execution

## Features

- Capture live packets from a network interface
- Log packet metadata to `logs/traffic_log.csv`
- Save captured packets to `captures/test.pcap`
- Generate suspicious packet reports in `reports/suspicious_report.csv`
- Supports IPv4 and IPv6 packet metadata
- Detects suspicious traffic using simple heuristic rules

## Installation

1. Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run PacketGuard with a network interface and optional duration:

```bash
python packet_guard.py --interface <interface-name> --duration 10
```

Example:

```bash
python packet_guard.py --interface eth0 --duration 15
```

### Optional arguments

- `--log`: CSV path for packet logs (default: `logs/traffic_log.csv`)
- `--pcap`: output PCAP file path (default: `captures/test.pcap`)
- `--report`: suspicious activity report path (default: `reports/suspicious_report.csv`)

## Output files

- `logs/traffic_log.csv`: packet metadata records
- `captures/test.pcap`: raw captured packet data
- `reports/suspicious_report.csv`: filtered suspicious packet records

## Sample workflow

1. Start capture on a valid interface.
2. PacketGuard logs packet metadata while capturing.
3. After capture, a suspicious activity report is generated.
4. Review the CSV report or open the PCAP in Wireshark for deeper analysis.

## Notes

- Packet capture usually requires elevated privileges (`sudo` or administrator access).
- This project is designed for demonstration and educational use, not for production security monitoring.
- The suspicious traffic rules are intentionally simple and can be expanded for stronger detection.

## Next improvements

- Add packet filtering by protocol, port, or IP range
- Improve suspicious traffic detection with multiple threat signatures
- Add unit tests for packet processing and reporting
- Add better error handling for invalid interfaces and permission issues
