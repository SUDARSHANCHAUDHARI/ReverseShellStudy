# Reverse Shell Study

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Safe lab metadata analyzer for suspicious outbound reverse-shell-like network behavior.

- **Portfolio group:** Cybersecurity lab project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/ReverseShellStudy
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/ReverseShellStudy`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

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

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
