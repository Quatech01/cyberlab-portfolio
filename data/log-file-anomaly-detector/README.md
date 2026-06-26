# Log File Anomaly Detector

A security tool that parses HTTP access logs and automatically flags five categories of suspicious activity: SQL injection attempts, directory traversal, known scanner user agents, request-rate spikes, and server error bursts.

## What This Demonstrates

Web servers generate access logs for every request. Attackers leave predictable footprints — SQL keywords in query strings, `../` sequences in URL paths, tool-specific user agent strings, and bursts of identical failed requests. A log analyser that knows these patterns can detect intrusion attempts in near real time, without touching production code or adding middleware.

This project shows how to build a rule-based anomaly detector that:

- Decodes URL-encoded paths before matching (catching `%2e%2e` and similar evasions)
- Uses sliding-window rate analysis to spot brute-force login attempts
- Tracks consecutive error streaks per IP to surface server abuse
- Distinguishes true positives from legitimate traffic without generating false alerts on browsers or curl

## How It Works

```
┌─────────────┐   GET /logs   ┌──────────────────┐
│  Demo Server│◄──────────────│  Anomaly Tool    │
│             │   JSON logs   │                  │
│  Seed logs  │──────────────►│  5 detection     │
│  + live     │               │  rules           │
│  request    │               │                  │
│  logging    │               │  JSON findings   │
└─────────────┘               └──────────────────┘
```

The demo server starts with pre-seeded log entries representing all five anomaly types, then records any live requests made during the session. The tool fetches all entries via `GET /logs`, applies its detection rules, and emits structured JSON findings with severity ratings.

Tests verify that:
- Each seeded anomaly type is correctly detected (true positives)
- Normal browser and curl traffic is never flagged (no false positives)
- The JSON output format is consistent and fully parseable

## Quick Start

```bash
# Install dependencies
cd server && npm install && cd ..
cd tool && npm install && cd ..
cd tests && npm install && cd ..

# Start the demo server
cd server && node index.js
# Server running on port 3000

# Run the detector (in a second terminal)
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "type": "sql_injection_attempt",
      "endpoint": "/api/users?id=1' OR '1'='1",
      "evidence": "SQL keyword or injection pattern detected in URL",
      "severity": "HIGH",
      "ip": "198.51.100.5",
      "timestamp": "2026-06-27T09:00:00.000Z"
    },
    {
      "type": "directory_traversal_attempt",
      "endpoint": "/../../../etc/passwd",
      "evidence": "Path traversal sequence (../ or URL-encoded equivalent) detected",
      "severity": "HIGH",
      "ip": "198.51.100.6",
      "timestamp": "2026-06-27T09:25:00.000Z"
    },
    {
      "type": "suspicious_user_agent",
      "endpoint": "/api/users",
      "evidence": "Known scanner or attack tool: sqlmap/1.0-dev-fffb696 (https://sqlmap.org)",
      "severity": "MEDIUM",
      "ip": "198.51.100.7",
      "timestamp": "2026-06-27T09:40:00.000Z"
    },
    {
      "type": "unusual_request_rate",
      "endpoint": "*",
      "evidence": "60 requests within 60 s from 198.51.100.8 (threshold: 30)",
      "severity": "MEDIUM",
      "ip": "198.51.100.8",
      "timestamp": "2026-06-27T09:45:00.000Z"
    },
    {
      "type": "error_spike",
      "endpoint": "/api/data",
      "evidence": "10 consecutive 5xx errors from 203.0.113.99",
      "severity": "MEDIUM",
      "ip": "203.0.113.99",
      "timestamp": "2026-06-27T09:50:00.000Z"
    }
  ],
  "summary": {
    "total_entries": 120,
    "anomalies_found": 15,
    "risk": "HIGH",
    "breakdown": {
      "sql_injection": 3,
      "directory_traversal": 3,
      "suspicious_ua": 4,
      "rate_anomaly": 1,
      "error_spike": 1
    }
  }
}
```

## Key Takeaways

- **Log analysis is cheap detection** — you don't need to touch running code. One pass over existing log files can reveal attacks that were already attempted.
- **URL-decode before matching** — attackers routinely encode `../` as `%2e%2e%2f` or `%252e%252e` to bypass naive string checks. Always decode before applying pattern rules.
- **Sliding-window rate limits catch brute force** — a single login failure is noise; 60 failures from one IP within a minute is a brute-force attack.
- **Consecutive error streaks signal abuse** — a burst of 5xx responses often means an attacker is hammering an endpoint or exploiting a crash-inducing bug.
- **Known tool user agents are reliable signals** — sqlmap, Nikto, masscan, and similar tools announce themselves. Matching these patterns catches a large fraction of automated scans with near-zero false positive rate.

## Further Reading

- [OWASP Testing Guide: Testing for Log Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/11-Testing_for_WebSockets_Security_Vulnerabilities)
- [OWASP: Log Monitoring and Alerting](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
