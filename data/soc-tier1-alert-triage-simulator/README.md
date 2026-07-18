# SOC Tier 1 Alert Triage Simulator

A full-stack Security Operations Centre training simulator that generates realistic ECS-formatted security alerts, streams them live to a browser dashboard, and includes a CLI pre-triage tool that automates deduplication and escalation recommendations.

## What This Demonstrates

Security analysts working Tier 1 in a SOC face a constant stream of security alerts from SIEM platforms like Elastic/Kibana. The challenge is not just detecting threats — it is triaging hundreds of alerts per shift, separating real incidents from noise, and routing the right alerts to Tier 2 analysts before they escalate into breaches.

This project teaches:

- **ECS (Elastic Common Schema)** — the standard alert format used by Elastic SIEM and Kibana Alerts
- **Alert triage workflow** — Escalate to Tier 2, Investigate, or Close as False Positive
- **Pre-triage automation** — deduplication by source IP + rule, false positive scoring, and escalation recommendations
- **SSE (Server-Sent Events)** for real-time alert streaming without WebSockets
- **SOC metrics** — tracking open/escalated/false-positive ratios as operational KPIs

## How It Works

```
server/main.py     FastAPI server that generates ECS alerts across 5 threat
                   categories, exposes REST and SSE endpoints, and serves the
                   HTML dashboard as a static file.

tool/main.py       CLI scanner that fetches open alerts, deduplicates by
                   (source_ip, rule_name), scores false-positive likelihood,
                   and outputs a structured JSON triage report.

frontend/index.html  Self-contained HTML/CSS/JS dashboard — no CDN dependencies.
                     Live alert table, triage buttons, stats cards, Canvas bar
                     chart, and SSE-powered real-time updates every 5 seconds.

tests/test.py      33 pytest tests covering: server health, alert generation
                   API, triage state transitions, SSE streaming, tool output
                   format, false positive suppression, and edge cases.
```

## Quick Start

```bash
# Install dependencies
cd server && pip install -r requirements.txt
cd ../tool && pip install -r requirements.txt

# Run the demo server
cd server && python main.py
# → http://127.0.0.1:3000  (dashboard)
# → http://127.0.0.1:3000/api/alerts  (alert list)

# Run the pre-triage tool
cd tool && python main.py --target http://localhost:3000

# Run the tests
cd tests && pip install -r requirements.txt && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/api/alerts",
      "vulnerability_type": "malware_beacon",
      "evidence": {
        "alert_id": "a3f1...",
        "rule": "C2 Beacon Interval Detected",
        "host": "workstation-05",
        "source_ip": "10.0.0.103",
        "severity": "critical",
        "fp_score": 0.0
      },
      "severity": "CRITICAL",
      "recommended_action": "escalate"
    },
    {
      "endpoint": "/api/alerts",
      "vulnerability_type": "port_scan",
      "evidence": {
        "rule": "Horizontal Port Scan",
        "source_ip": "10.0.0.108",
        "severity": "low",
        "fp_score": 0.7
      },
      "severity": "LOW",
      "recommended_action": "close_fp"
    }
  ],
  "summary": {
    "total_open": 15,
    "after_dedup": 12,
    "recommended_escalate": 4,
    "recommended_investigate": 5,
    "recommended_close_fp": 3
  }
}
```

## Key Takeaways

- **ECS field naming** (`kibana.alert.severity`, `event.category`, `host.name`, `source.ip`) mirrors production Kibana — skills transfer directly to real SIEM environments.
- **Deduplication is essential** — the same source IP firing the same rule 10 times is one incident, not 10. The tool groups by `(source_ip, rule_name)` before reporting.
- **False positive scoring reduces fatigue** — port scans and brute-force attempts from IPs that already appear frequently are likely scanner noise. Scoring prevents alert fatigue from burying real threats.
- **Escalation thresholds matter** — lateral movement, privilege escalation, and malware beacon categories always escalate when severity is critical or high; low-severity network noise does not.
- **SSE vs WebSockets** — Server-Sent Events are simpler for one-directional server→client streaming and require no protocol upgrade handshake, making them ideal for alert feeds.

## Further Reading

- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [OWASP Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
