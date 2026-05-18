# Reverse Shell Study

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-lab%20polish-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Safe lab metadata analyzer for suspicious outbound reverse-shell-like network behavior.

- **Portfolio group:** Cybersecurity lab project
- **Status:** Lab polish implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/ReverseShellStudy
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/ReverseShellStudy`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection logic, local tests, generated findings, summary JSON, timeline output, and Docker demo support.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

## Core Features

- load .pcap metadata
- detect unusual outbound connection
- show destination IP/port
- explain why suspicious
- show source, protocol, timestamp, score, and recommended response
- generate summary and timeline reports

## Safety Note

Use only in your own lab environment.

## Quick Start

```bash
python3 -m analysis.suspicious_outbound data/safe-lab-sample.pcap
python3 -m unittest discover -s tests -p 'test_*.py'
```

The sample `.pcap` is sanitized JSON metadata for lab analysis. It does not contain exploit payloads or live packet traffic.

Generated outputs:

- `docs/FINDINGS.md`
- `reports/findings.json`
- `reports/summary.json`
- `reports/timeline.md`

## Docker Demo

```bash
docker compose run --rm reverse-shell-study
```

## Lab Polish Capabilities

- Loads safe lab capture metadata
- Scores unusual outbound destination ports
- Flags shell-like processes opening remote-control connections
- Explains why a connection is suspicious
- Writes Markdown, JSON, summary, and timeline outputs
- Adds destination risk rollups and recommended response actions

## Roadmap

- Add process ancestry metadata support
- Add allow-list support for known admin tunnels
- Add destination reputation enrichment as an optional offline fixture
- Add dashboard view for timeline and destination risk
- Prepare a tagged lab-polish release
