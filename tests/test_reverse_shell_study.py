from pathlib import Path
import unittest

from analysis.connection_analyzer import analyze_connections
from analysis.pcap_reader import load_capture_metadata, summarize_capture
from analysis.suspicious_outbound import build_report


ROOT = Path(__file__).resolve().parents[1]


class ReverseShellStudyTests(unittest.TestCase):
    def test_load_capture_metadata(self) -> None:
        records = load_capture_metadata(ROOT / "data/safe-lab-sample.pcap")
        summary = summarize_capture(records)

        self.assertEqual(3, summary["connections"])
        self.assertEqual(3, summary["outbound"])

    def test_detects_reverse_shell_like_connection(self) -> None:
        records = load_capture_metadata(ROOT / "data/safe-lab-sample.pcap")
        findings = analyze_connections(records)

        self.assertEqual(1, len(findings))
        self.assertEqual("198.51.100.44", findings[0].destination_ip)
        self.assertEqual("high", findings[0].risk)
        self.assertIn("interactive process", findings[0].reason)

    def test_report_explains_destination(self) -> None:
        records = load_capture_metadata(ROOT / "data/safe-lab-sample.pcap")
        report = build_report(records, analyze_connections(records))

        self.assertIn("Reverse Shell Study Findings", report)
        self.assertIn("198.51.100.44:4444", report)


if __name__ == "__main__":
    unittest.main()
