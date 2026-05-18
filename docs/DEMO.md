# Demo

## Local CLI

```bash
python3 -m analysis.suspicious_outbound data/safe-lab-sample.pcap
```

Expected terminal output:

```text
Analyzed 3 connection(s)
Detected 1 suspicious outbound connection(s)
```

## Review Outputs

```bash
cat docs/FINDINGS.md
cat reports/timeline.md
cat reports/summary.json
```

## Docker CLI

```bash
docker compose run --rm reverse-shell-study
```
