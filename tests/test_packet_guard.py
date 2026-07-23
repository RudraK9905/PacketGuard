import csv
import tempfile
import unittest
from pathlib import Path

from packet_guard import PacketGuard


class PacketGuardDemoModeTests(unittest.TestCase):
    def test_demo_mode_creates_report_and_log(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            guard = PacketGuard(
                log_path=tmp_path / "traffic.csv",
                pcap_path=tmp_path / "capture.pcap",
                report_path=tmp_path / "report.csv",
            )

            packets = guard.start_capture(interface=None, duration=3, demo=True)

            self.assertGreater(len(packets), 0)
            self.assertTrue(guard.log_path.exists())
            self.assertTrue(guard.report_path.exists())

            with guard.log_path.open(newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertGreater(len(rows), 0)

            suspicious = guard.generate_report()
            self.assertGreater(len(suspicious), 0)


if __name__ == "__main__":
    unittest.main()
