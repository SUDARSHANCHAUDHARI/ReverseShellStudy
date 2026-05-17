# Reverse Shell Study

**Goal:** Understand reverse shell network behavior.

**MVP:** Analyze safe lab packet captures.

## Core Features

- load .pcap metadata
- detect unusual outbound connection
- show destination IP/port
- explain why suspicious

## Safety Note

Use only in your own lab environment.

## Quick Start

```bash
python3 -m analysis.suspicious_outbound data/safe-lab-sample.pcap
python3 -m unittest discover -s tests -p 'test_*.py'
```

The sample `.pcap` is sanitized JSON metadata for lab analysis. It does not contain exploit payloads or live packet traffic.

## MVP Capabilities

- Loads safe lab capture metadata
- Scores unusual outbound destination ports
- Flags shell-like processes opening remote-control connections
- Explains why a connection is suspicious
- Writes `docs/FINDINGS.md` and `reports/findings.json`

## Repository Status

This repository contains a working, analysis-only Reverse Shell Study MVP with safe lab data, deterministic findings, reports, and tests.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
