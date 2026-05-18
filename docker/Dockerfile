FROM python:3.12-slim

WORKDIR /app
COPY . .

CMD ["python", "-m", "analysis.suspicious_outbound", "data/safe-lab-sample.pcap"]
