# Architecture

Reverse Shell Study is a defensive lab analyzer for sanitized packet-capture metadata.

## Flow

1. `analysis/pcap_reader.py` loads JSON metadata from `data/safe-lab-sample.pcap`.
2. `analysis/connection_analyzer.py` scores outbound sessions using deterministic indicators.
3. `analysis/suspicious_outbound.py` writes findings, summary, and timeline reports.

## Detection Inputs

- timestamp
- source IP
- destination IP
- destination port
- protocol
- bytes out
- direction
- process name

## Outputs

- `docs/FINDINGS.md`
- `reports/findings.json`
- `reports/summary.json`
- `reports/timeline.md`

The project intentionally avoids live packet capture and exploit tooling.
