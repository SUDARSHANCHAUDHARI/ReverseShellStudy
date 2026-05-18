from pathlib import Path
import unittest

from analysis.connection_analyzer import analyze_connections
from analysis.pcap_reader import load_capture_metadata, summarize_capture
from analysis.suspicious_outbound import build_report, build_summary_json, build_timeline_report


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
        self.assertEqual("10.10.10.15", findings[0].source_ip)
        self.assertIn("Isolate the lab host", findings[0].recommended_action)

    def test_report_explains_destination(self) -> None:
        records = load_capture_metadata(ROOT / "data/safe-lab-sample.pcap")
        report = build_report(records, analyze_connections(records))

        self.assertIn("Reverse Shell Study Findings", report)
        self.assertIn("198.51.100.44:4444", report)

    def test_builds_summary_and_timeline_outputs(self) -> None:
        records = load_capture_metadata(ROOT / "data/safe-lab-sample.pcap")
        findings = analyze_connections(records)
        summary = build_summary_json(records, findings)
        timeline = build_timeline_report(findings)

        self.assertIn('"high_risk_findings": 1', summary)
        self.assertIn("destination_risk", summary)
        self.assertIn("Reverse Shell Study Timeline", timeline)
        self.assertIn("198.51.100.44:4444", timeline)


if __name__ == "__main__":
    unittest.main()
