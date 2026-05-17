"""Analyze outbound connections for reverse-shell-like indicators."""

from __future__ import annotations

from dataclasses import dataclass

from analysis.pcap_reader import ConnectionRecord


REMOTE_ADMIN_PORTS = {22, 2222, 4444, 5555, 9001, 1337}
EXPECTED_OUTBOUND_PORTS = {53, 80, 123, 443}
SHELL_PROCESS_HINTS = {"bash", "sh", "zsh", "nc", "ncat", "netcat", "python", "perl", "ruby"}


@dataclass(frozen=True)
class ConnectionFinding:
    destination_ip: str
    destination_port: int
    process: str
    risk: str
    score: int
    reason: str


def score_connection(record: ConnectionRecord) -> ConnectionFinding | None:
    if record.direction != "outbound":
        return None

    score = 0
    reasons: list[str] = []
    process = record.process.lower()

    if record.destination_port in REMOTE_ADMIN_PORTS:
        score += 35
        reasons.append(f"unusual remote-control port {record.destination_port}")
    if record.destination_port not in EXPECTED_OUTBOUND_PORTS:
        score += 20
        reasons.append("destination port is outside normal web, DNS, or NTP traffic")
    if process in SHELL_PROCESS_HINTS:
        score += 30
        reasons.append(f"interactive process '{record.process}' opened the connection")
    if record.bytes_out < 2048 and record.destination_port not in {53, 123}:
        score += 10
        reasons.append("low-volume session can match command-and-control behavior")

    if score < 40:
        return None
    risk = "high" if score >= 70 else "medium"
    return ConnectionFinding(
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        process=record.process,
        risk=risk,
        score=score,
        reason="; ".join(reasons),
    )


def analyze_connections(records: list[ConnectionRecord]) -> list[ConnectionFinding]:
    findings = [finding for record in records if (finding := score_connection(record))]
    return sorted(findings, key=lambda finding: (-finding.score, finding.destination_ip))
