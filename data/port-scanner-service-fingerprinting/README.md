# Port Scanner with Service Fingerprinting

A TCP port scanner that identifies running services by analysing the banner or response each open port returns — no external libraries required.

## What This Demonstrates

**Service fingerprinting** is the technique of identifying *what* is listening on an open port, not just *that* something is there. Scanners like Nmap do this at scale; this project builds the same idea from scratch.

Every network service has a characteristic response pattern:

- **HTTP servers** reply to any request with `HTTP/1.x` — making them trivially identifiable.
- **SMTP servers** send an unsolicited `220 hostname ESMTP …` greeting the moment a client connects — you don't even have to ask.
- **TCP echo services** (debug/test daemons) reflect back exactly what you send them.

Understanding these patterns is essential for both offensive recon (finding unexpected attack surface) and defensive auditing (knowing what you're actually exposing).

## How It Works

```
demo server (server/)          scanner tool (tool/)
────────────────────           ────────────────────
:httpPort   → Express HTTP  ←─ TCP connect + HTTP probe → fingerprint as "http"
:httpPort+1 → TCP echo      ←─ TCP connect + HTTP probe → echoed back → "echo"
:httpPort+2 → Fake SMTP     ←─ TCP connect → 220 banner → fingerprint as "smtp"
```

The scanner:
1. Parses a `--target` URL to extract hostname and base port.
2. Opens parallel TCP connections to every port in the scan range (`basePort` to `basePort + range`).
3. Sends an HTTP HEAD probe to each open port.
4. Classifies the response by pattern matching.
5. Emits a JSON report followed by a human-readable summary.

The tests start the demo server in-process on a random port, run the scanner as a child process against it, and assert on the JSON output.

## Quick Start

```bash
# Install server dependencies
cd server && npm install

# Run the demo server (opens 3 ports: N, N+1, N+2)
node server/index.js

# In another terminal — scan the default port range
node tool/index.js --target http://localhost:3000

# Run the test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "host": "localhost",
  "portRange": "3000-3010",
  "scanTime": "2026-05-26T14:00:00.000Z",
  "findings": [
    {
      "endpoint": "localhost:3000",
      "port": 3000,
      "state": "open",
      "vulnerability_type": "exposed-service",
      "service": "http",
      "version": "DemoApp/1.0 (Node.js/Express)",
      "evidence": "HTTP/1.1 200 OK\\r\\nServer: DemoApp/1.0...",
      "confidence": "HIGH",
      "severity": "INFO"
    },
    {
      "endpoint": "localhost:3001",
      "port": 3001,
      "state": "open",
      "vulnerability_type": "exposed-service",
      "service": "echo",
      "version": "TCP echo (raw)",
      "evidence": "HEAD / HTTP/1.0\\r\\nHost: localhost...",
      "confidence": "HIGH",
      "severity": "INFO"
    },
    {
      "endpoint": "localhost:3002",
      "port": 3002,
      "state": "open",
      "vulnerability_type": "exposed-service",
      "service": "smtp",
      "version": "mail.demo.local ESMTP DemoSMTP 1.0 Ready",
      "evidence": "220 mail.demo.local ESMTP DemoSMTP...",
      "confidence": "HIGH",
      "severity": "MEDIUM"
    }
  ],
  "summary": {
    "openPorts": 3,
    "closedPorts": 8,
    "servicesDetected": ["http", "echo", "smtp"],
    "riskLevel": "MEDIUM"
  }
}
```

## Key Takeaways

- **Banners are information leakage.** Server headers (`Server: Apache/2.4.51`) and greeting messages tell an attacker exactly what software version you're running before they send a single malicious byte.
- **Parallel TCP probing is fast.** All port probes run concurrently via `Promise.all` — latency is bounded by the slowest single port, not the sum of all ports.
- **Unsolicited banners are the most reliable fingerprint.** Services like SMTP and FTP announce themselves before the client says anything, making them easy to find even with a dumb scanner.
- **TCP echo services are a real risk.** Exposed echo daemons are used in amplification attacks and can leak internal network topology to anyone who can reach them.

## Further Reading

- [OWASP Testing Guide — Network Infrastructure Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [RFC 5321 — Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321)
- [IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
