"""CLI report builder for suspicious outbound lab traffic."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from analysis.connection_analyzer import ConnectionFinding, analyze_connections
from analysis.pcap_reader import ConnectionRecord, load_capture_metadata, summarize_capture


def build_report(records: list[ConnectionRecord], findings: list[ConnectionFinding]) -> str:
    summary = summarize_capture(records)
    lines = [
        "# Reverse Shell Study Findings",
        "",
        "Safe lab metadata was analyzed for unusual outbound connection behavior.",
        "",
        f"- Connections analyzed: {summary['connections']}",
        f"- Outbound connections: {summary['outbound']}",
        f"- Unique destinations: {summary['unique_destinations']}",
        f"- Findings: {len(findings)}",
        "",
        "## Suspicious Outbound Connections",
        "",
    ]
    if not findings:
        lines.append("No reverse-shell-like outbound behavior was detected.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.destination_ip}:{finding.destination_port}",
                "",
                f"- Risk: {finding.risk}",
                f"- Score: {finding.score}",
                f"- Process: {finding.process}",
                f"- Why suspicious: {finding.reason}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze safe lab capture metadata for suspicious outbound sessions")
    parser.add_argument("capture", type=Path, nargs="?", default=Path("data/safe-lab-sample.pcap"))
    parser.add_argument("--out", type=Path, default=Path("docs/FINDINGS.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/findings.json"))
    args = parser.parse_args()

    records = load_capture_metadata(args.capture)
    findings = analyze_connections(records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_report(records, findings), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(finding) for finding in findings], indent=2) + "\n", encoding="utf-8")
    print(f"Analyzed {len(records)} connection(s)")
    print(f"Detected {len(findings)} suspicious outbound connection(s)")


if __name__ == "__main__":
    main()
