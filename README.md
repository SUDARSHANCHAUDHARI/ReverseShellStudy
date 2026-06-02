# Reverse Shell Study

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-MVP-green)](#status)
[![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#safe-use)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Safe lab metadata analyzer for suspicious outbound reverse-shell-like network behavior. Reads packet capture metadata (no payloads), flags interactive outbound sessions to non-standard ports, and recommends host isolation actions.

---

## Overview

Reverse Shell Study is a defensive analysis lab tool for studying reverse-shell traffic patterns without handling real payloads. It reads pcap metadata (connection records only, no packet content), analyzes outbound connections to suspicious destinations and ports, and flags interactive-session indicators (low data, long duration, persistent unidirectional flow to a non-standard port). Outputs include findings, risk-scored summary, Markdown report, timeline, and analyst triage handoff.

## Features

- Reads pcap-style connection metadata (no payloads)
- Analyzes outbound connections per host
- Flags suspicious destination IPs and non-standard ports
- Detects interactive-process traffic patterns
- Risk-scores each finding with recommended response actions
- Outputs JSON findings, summary, Markdown report, timeline, and triage handoff

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- No third-party Python packages (standard library only)
- Optional: Docker for the demo container

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/ReverseShellStudy.git
cd ReverseShellStudy
pip install .
```

This registers the `reverse-shell-study` CLI command.

To run without installing:

```bash
python3 main.py --help
```

## Usage

Analyze the included safe lab sample:

```bash
python3 main.py --out reports/report.md
```

Generated outputs in `reports/`:

- `findings.json` — detected reverse-shell-like findings
- `summary.json` — counts and severity breakdown
- `report.md` — Markdown analysis report
- `timeline.md` — chronological timeline of suspect connections
- `triage.md` — analyst triage checklist

## Project Structure

```
ReverseShellStudy/
├── analysis/       Connection analyzer, pcap metadata reader, suspicious outbound detector
├── data/           Safe sample lab capture metadata
├── reports/        Example generated output
├── docker/         Dockerfile + compose support
├── docs/           Architecture, security notes, demo
├── tests/          Unit tests
├── main.py         CLI entrypoint
├── pyproject.toml  Package metadata
└── LICENSE
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Docker Demo

```bash
docker compose run --rm reverse-shell-demo
```

## Safe Use

This project is defensive and analysis-focused. It deliberately reads only connection metadata, not packet payloads. Use only with lab captures and environments you own or have explicit written permission to assess. The included sample is synthetic and safe for public demo use.

## Status

Working CLI MVP with tests, sample data, and Docker support.

## Roadmap

- Real pcap parsing (still metadata-only — no payload exposure)
- Process-attribution heuristics (Linux netstat / ss correlation)
- Allowlist for known good outbound services
- Timeline visualization
- GitHub release `v0.1.0-mvp`

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software with attribution.

## Author

**Sudarshan Chaudhari** — [SudarshanTechLabs](https://github.com/SUDARSHANCHAUDHARI)
Bangkok, Thailand

For inquiries: open an issue on [GitHub](https://github.com/SUDARSHANCHAUDHARI/ReverseShellStudy/issues).
