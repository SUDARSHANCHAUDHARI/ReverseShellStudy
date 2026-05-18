"""CLI report builder for suspicious outbound lab traffic."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from analysis.connection_analyzer import ConnectionFinding, analyze_connections, build_destination_risk
from analysis.pcap_reader import ConnectionRecord, load_capture_metadata, summarize_capture


def build_report(records: list[ConnectionRecord], findings: list[ConnectionFinding]) -> str:
    summary = summarize_capture(records)
    destination_risk = build_destination_risk(findings)
    lines = [
        "# Reverse Shell Study Findings",
        "",
        "Safe lab metadata was analyzed for unusual outbound connection behavior.",
        "",
        f"- Connections analyzed: {summary['connections']}",
        f"- Outbound connections: {summary['outbound']}",
        f"- Unique destinations: {summary['unique_destinations']}",
        f"- Findings: {len(findings)}",
        f"- High risk findings: {sum(1 for finding in findings if finding.risk == 'high')}",
        "",
        "## Priority Queue",
        "",
    ]
    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.append(
                f"{index}. `{finding.source_ip}` -> `{finding.destination_ip}:{finding.destination_port}` via `{finding.process}` ({finding.risk}, score {finding.score})"
            )
    else:
        lines.append("No reverse-shell-like outbound behavior was detected.")
    lines.extend(
        [
            "",
            "## Destination Risk",
            "",
        ]
    )
    if destination_risk:
        for row in destination_risk:
            lines.append(
                f"- `{row['destination_ip']}`: {row['highest_risk']} risk, score {row['highest_score']}, ports {row['ports']}, processes {row['processes']}"
            )
    else:
        lines.append("No suspicious destinations were identified.")
    lines.extend(
        [
            "",
            "## Suspicious Outbound Connections",
            "",
        ]
    )
    if not findings:
        lines.append("No reverse-shell-like outbound behavior was detected.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.destination_ip}:{finding.destination_port}",
                "",
                f"- Timestamp: {finding.timestamp}",
                f"- Source: {finding.source_ip}",
                f"- Risk: {finding.risk}",
                f"- Score: {finding.score}",
                f"- Protocol: {finding.protocol}",
                f"- Process: {finding.process}",
                f"- Why suspicious: {finding.reason}",
                f"- Recommended action: {finding.recommended_action}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def build_summary_json(records: list[ConnectionRecord], findings: list[ConnectionFinding]) -> str:
    summary = summarize_capture(records)
    summary.update(
        {
            "findings": len(findings),
            "high_risk_findings": sum(1 for finding in findings if finding.risk == "high"),
            "highest_score": max((finding.score for finding in findings), default=0),
            "destination_risk": build_destination_risk(findings),
        }
    )
    return json.dumps(summary, indent=2) + "\n"


def build_timeline_report(findings: list[ConnectionFinding]) -> str:
    lines = [
        "# Reverse Shell Study Timeline",
        "",
    ]
    if not findings:
        lines.append("No suspicious outbound timeline entries were identified.")
    for finding in sorted(findings, key=lambda item: item.timestamp):
        lines.extend(
            [
                f"## {finding.timestamp}",
                "",
                f"- Source: `{finding.source_ip}`",
                f"- Destination: `{finding.destination_ip}:{finding.destination_port}`",
                f"- Process: `{finding.process}`",
                f"- Risk: {finding.risk}",
                f"- Action: {finding.recommended_action}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze safe lab capture metadata for suspicious outbound sessions")
    parser.add_argument("capture", type=Path, nargs="?", default=Path("data/safe-lab-sample.pcap"))
    parser.add_argument("--out", type=Path, default=Path("docs/FINDINGS.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/findings.json"))
    parser.add_argument("--summary-out", type=Path, default=Path("reports/summary.json"))
    parser.add_argument("--timeline-out", type=Path, default=Path("reports/timeline.md"))
    args = parser.parse_args()

    records = load_capture_metadata(args.capture)
    findings = analyze_connections(records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_report(records, findings), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(finding) for finding in findings], indent=2) + "\n", encoding="utf-8")
    args.summary_out.write_text(build_summary_json(records, findings), encoding="utf-8")
    args.timeline_out.write_text(build_timeline_report(findings), encoding="utf-8")
    print(f"Analyzed {len(records)} connection(s)")
    print(f"Detected {len(findings)} suspicious outbound connection(s)")


if __name__ == "__main__":
    main()
