# Rate Limit Bypass Tester

A security scanner that detects HTTP rate limiting implementations that can be circumvented by rotating the `X-Forwarded-For` header. A common flaw in reverse-proxy-aware applications is trusting the client-supplied header as a source of truth for the requester's IP address — attackers exploit this to mount unlimited brute-force attempts against login endpoints.

## What This Demonstrates

Rate limiting is a critical control against brute-force credential attacks. Many web frameworks offer middleware that keys rate limits by "client IP". When that middleware reads `X-Forwarded-For` (or `X-Real-IP`) without validating that the header came from a trusted proxy, it delegates trust to the very client it is trying to restrict.

An attacker can send:

```
POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.4
```

After hitting the limit under that fake IP, they change the header to `X-Forwarded-For: 2.3.4.5` and the counter resets — unlimited attempts resume. No IP rotation, VPN, or Tor required.

The safe countermeasure is to key rate limits by `request.client.host`, the actual TCP connection peer address. A client cannot forge their socket-level IP without controlling the network path.

## How It Works

```
┌─────────────────────┐     HTTP     ┌─────────────────────┐
│  tool/main.py       │◄────────────►│  server/main.py     │
│  (bypass scanner)   │             │  (FastAPI demo)     │
└─────────────────────┘             │                     │
                                    │  /api/vulnerable/*  │  keyed by X-Forwarded-For
                                    │  /api/safe/*        │  keyed by TCP socket IP
                                    │  /api/admin/reset   │  test reset endpoint
                                    └─────────────────────┘
```

The demo server exposes two login endpoints with identical behaviour but different rate limiting strategies:

| Endpoint | Rate limit key | Bypassable? |
|---|---|---|
| `POST /api/vulnerable/login` | `X-Forwarded-For` header value | **Yes** — rotate the header |
| `POST /api/safe/login` | Actual TCP connection IP | No |

The scanner:
1. Fetches `/api/probe-targets` to discover endpoints and the configured limit.
2. For each endpoint, exhausts the rate limit using a fixed fake IP, then rotates to a new fake IP.
3. A `200` response after rotation confirms the bypass; a `429` confirms the limit held.
4. Outputs structured JSON findings with severity ratings.

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt

# Install tool dependencies
cd ../tool && pip install -r requirements.txt

# Run the demo server (port 3000)
cd ../server && python main.py
```

In a second terminal:

```bash
# Run the scanner
cd tool && python main.py --target http://localhost:3000
```

Run the full test suite:

```bash
cd tests && pip install -r requirements.txt && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/api/vulnerable/login",
      "vulnerability_type": "RATE_LIMIT_BYPASS_VIA_HEADER",
      "evidence": "Rate limit of 5 req/window was exhausted using X-Forwarded-For: 203.0.113.10 (HTTP 429 confirmed). Rotating the header to X-Forwarded-For: 203.0.113.20 immediately returned HTTP 200, proving the limit is keyed by the spoofable header rather than the actual TCP connection IP.",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 1 rate limit bypass vulnerability across 2 endpoint(s). The affected endpoint keys its rate limit on the X-Forwarded-For header, which any client can set to an arbitrary value. Rotating this header allows unlimited requests, defeating the intended brute-force protection."
}
```

## Key Takeaways

- **Never trust client-supplied headers as identity primitives.** `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` can all be forged by any HTTP client.
- **Key rate limits on `request.client.host`** (the OS-level TCP peer address). This cannot be spoofed without compromising the network path between the client and server.
- **If your app sits behind a trusted reverse proxy** (NGINX, Cloudflare, AWS ALB), configure the proxy to overwrite rather than append the forwarded-IP header, and only read it at the proxy layer — not in application code.
- **Rate limiting is not a replacement for account lockout.** A rate limit keyed by IP can always be bypassed by an attacker with many IPs. Combine it with per-account lockout and CAPTCHA challenges for defence in depth.

## Further Reading

- [OWASP — Testing for Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- [OWASP — Testing for Rate Limiting](https://owasp.org/www-community/attacks/Brute_force_attack)
- [RFC 7239 — Forwarded HTTP Extension](https://datatracker.ietf.org/doc/html/rfc7239) — the standard for forwarded-IP headers and their trust model
