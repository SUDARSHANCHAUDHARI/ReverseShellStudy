# Reverse Shell Study Findings

Safe lab metadata was analyzed for unusual outbound connection behavior.

- Connections analyzed: 3
- Outbound connections: 3
- Unique destinations: 3
- Findings: 1

## Suspicious Outbound Connections

### 198.51.100.44:4444

- Risk: high
- Score: 95
- Process: bash
- Why suspicious: unusual remote-control port 4444; destination port is outside normal web, DNS, or NTP traffic; interactive process 'bash' opened the connection; low-volume session can match command-and-control behavior
