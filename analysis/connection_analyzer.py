"""Analyze outbound connections for reverse-shell-like indicators."""

from __future__ import annotations

from dataclasses import dataclass

from analysis.pcap_reader import ConnectionRecord


REMOTE_ADMIN_PORTS = {22, 2222, 4444, 5555, 9001, 1337}
EXPECTED_OUTBOUND_PORTS = {53, 80, 123, 443}
SHELL_PROCESS_HINTS = {"bash", "sh", "zsh", "nc", "ncat", "netcat", "python", "perl", "ruby"}


@dataclass(frozen=True)
class ConnectionFinding:
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    process: str
    risk: str
    score: int
    reason: str
    recommended_action: str


def recommended_action_for(score: int) -> str:
    if score >= 70:
        return "Isolate the lab host, preserve process/network evidence, and confirm whether the outbound session was authorized."
    return "Review process ancestry and destination reputation before closing the finding."


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
        timestamp=record.timestamp.isoformat(),
        source_ip=record.source_ip,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        protocol=record.protocol,
        process=record.process,
        risk=risk,
        score=score,
        reason="; ".join(reasons),
        recommended_action=recommended_action_for(score),
    )


def analyze_connections(records: list[ConnectionRecord]) -> list[ConnectionFinding]:
    findings = [finding for record in records if (finding := score_connection(record))]
    return sorted(findings, key=lambda finding: (-finding.score, finding.destination_ip))


def build_destination_risk(findings: list[ConnectionFinding]) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for finding in findings:
        row = rows.setdefault(
            finding.destination_ip,
            {
                "destination_ip": finding.destination_ip,
                "highest_score": finding.score,
                "highest_risk": finding.risk,
                "ports": [],
                "processes": [],
                "finding_count": 0,
            },
        )
        row["highest_score"] = max(int(row["highest_score"]), finding.score)
        row["highest_risk"] = "high" if int(row["highest_score"]) >= 70 else "medium"
        row["finding_count"] = int(row["finding_count"]) + 1
        ports = row["ports"]
        processes = row["processes"]
        assert isinstance(ports, list)
        assert isinstance(processes, list)
        if finding.destination_port not in ports:
            ports.append(finding.destination_port)
        if finding.process not in processes:
            processes.append(finding.process)
    return sorted(rows.values(), key=lambda row: (-int(row["highest_score"]), str(row["destination_ip"])))
