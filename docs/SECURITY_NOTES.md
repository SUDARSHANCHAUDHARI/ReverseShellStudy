# Security Notes

This project is defensive and lab-only.

## Safe Use

- Use only captures and metadata from systems you own or have permission to assess.
- Do not commit real packet captures, secrets, credentials, customer traffic, or internal IP inventories.
- Treat findings as sensitive because they may reveal host behavior and detection gaps.

## Scope

The repository does not include reverse shell payloads, exploit code, or live traffic collection. The sample `.pcap` file is sanitized JSON metadata used for local analysis.

## Before Sharing

Review:

- capture metadata
- generated findings
- generated timeline
- screenshots or terminal recordings
