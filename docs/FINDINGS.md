# Reverse Shell Study Findings

Safe lab metadata was analyzed for unusual outbound connection behavior.

- Connections analyzed: 3
- Outbound connections: 3
- Unique destinations: 3
- Findings: 1
- High risk findings: 1

## Priority Queue

1. `10.10.10.15` -> `198.51.100.44:4444` via `bash` (high, score 95)

## Destination Risk

- `198.51.100.44`: high risk, score 95, ports [4444], processes ['bash']

## Suspicious Outbound Connections

### 198.51.100.44:4444

- Timestamp: 2026-05-18T11:01:00+00:00
- Source: 10.10.10.15
- Risk: high
- Score: 95
- Protocol: TCP
- Process: bash
- Why suspicious: unusual remote-control port 4444; destination port is outside normal web, DNS, or NTP traffic; interactive process 'bash' opened the connection; low-volume session can match command-and-control behavior
- Recommended action: Isolate the lab host, preserve process/network evidence, and confirm whether the outbound session was authorized.
