"""Read safe packet-capture metadata for reverse shell behavior study."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path


@dataclass(frozen=True)
class ConnectionRecord:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    bytes_out: int
    direction: str
    process: str


def _record_from_dict(raw: dict) -> ConnectionRecord:
    return ConnectionRecord(
        timestamp=datetime.fromisoformat(str(raw["timestamp"]).replace("Z", "+00:00")),
        source_ip=str(raw["source_ip"]),
        destination_ip=str(raw["destination_ip"]),
        destination_port=int(raw["destination_port"]),
        protocol=str(raw.get("protocol", "tcp")).upper(),
        bytes_out=int(raw.get("bytes_out", 0)),
        direction=str(raw.get("direction", "outbound")).lower(),
        process=str(raw.get("process", "unknown")),
    )


def load_capture_metadata(path: Path) -> list[ConnectionRecord]:
    """Load JSON metadata exported from a safe lab capture.

    This MVP intentionally avoids raw packet parsing and focuses on detection
    logic over sanitized connection summaries.
    """
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    payload = json.loads(text)
    if not isinstance(payload, list):
        raise ValueError("capture metadata must be a JSON list")
    return sorted((_record_from_dict(item) for item in payload), key=lambda record: record.timestamp)


def summarize_capture(records: list[ConnectionRecord]) -> dict[str, int]:
    return {
        "connections": len(records),
        "outbound": sum(1 for record in records if record.direction == "outbound"),
        "unique_destinations": len({record.destination_ip for record in records}),
    }
