# Rate Limiting Middleware

Three rate limiting algorithms implemented from scratch — token bucket, fixed window, and sliding window — with a scanner that detects unprotected endpoints and demonstrates the fixed-window boundary-burst vulnerability.

## What This Demonstrates

Rate limiting is a critical defence against brute-force attacks, credential stuffing, and denial-of-service. There are several common algorithms, each with different trade-offs:

- **Token Bucket**: Allows short bursts up to a configured capacity, then replenishes tokens at a steady rate. No fixed window boundary, so there is no burst exploit at a predictable reset moment.
- **Fixed Window**: Counts requests in a fixed time period (e.g., 5 requests per 2 seconds). Simple and cheap, but susceptible to a *boundary burst*: an attacker can fire max requests just before the window ends and max more requests immediately after it resets — effectively doubling their throughput at every window boundary.
- **Sliding Window**: Tracks individual request timestamps in a rolling window. Because the window moves continuously, there is no fixed boundary to exploit. The sliding window is strictly superior to fixed window for brute-force defence at the cost of slightly higher memory use.

## How It Works

```
server/main.py        — FastAPI server with four endpoints:
                        /api/no-limit        no rate limiting (vulnerable)
                        /api/token-bucket    token bucket (5 cap, 2.5/sec refill)
                        /api/fixed-window    fixed window  (5 req / 2 sec)
                        /api/sliding-window  sliding window (5 req / 2 sec)
                        /api/admin/reset     resets all limiter state (for tests)

tool/main.py          — Scanner that:
                        1. Fires 15 rapid requests at each endpoint
                        2. Flags endpoints that never return 429 (MISSING_RATE_LIMITING)
                        3. Tests fixed-window boundary burst: fills window, waits for
                           reset, fires another batch — flags if 2× limit succeeds

tests/test.py         — 26 pytest tests covering all five groups
```

## Quick Start

```bash
# Install dependencies
cd server && pip install -r requirements.txt
cd ../tool  && pip install -r requirements.txt
cd ../tests && pip install -r requirements.txt

# Run the demo server
cd ../server && python main.py
# Server starts on http://localhost:3000

# Run the scanner (in another terminal)
cd ../tool && python main.py --target http://localhost:3000

# Run the test suite
cd ../tests && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/api/no-limit",
      "vulnerability_type": "MISSING_RATE_LIMITING",
      "evidence": "Sent 15 rapid requests; all returned HTTP 200 — endpoint applies no rate limit whatsoever",
      "severity": "HIGH"
    },
    {
      "endpoint": "/api/fixed-window",
      "vulnerability_type": "FIXED_WINDOW_BURST",
      "evidence": "5 requests succeeded at the end of window 1; after 2.0s reset, 5 more succeeded immediately at the start of window 2 — 10 requests processed in ~2.0s (2× the configured limit of 5/window). An attacker can time requests to straddle the boundary and effectively double their throughput.",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Found 2 issue(s): /api/no-limit: no rate limiting (HIGH); /api/fixed-window: boundary burst 10 req in ~2.0s (MEDIUM). Token bucket and sliding window correctly enforce their limits."
}
```

## Key Takeaways

1. **A missing rate limit is always HIGH severity** — login endpoints without limiting are directly vulnerable to brute-force credential guessing.
2. **Fixed-window algorithms are exploitable at boundaries** — an attacker who times their requests to straddle the window reset can double effective throughput. Use sliding window for endpoints where this matters (authentication, payment, high-value operations).
3. **Token bucket handles legitimate traffic bursts better** — a user who sends 5 requests at once is not blocked if tokens are available; subsequent requests are shaped, not hard-blocked. This is why CDNs and API gateways often prefer token bucket.
4. **Sliding window eliminates the boundary burst** but requires O(n) memory per client per window (storing individual timestamps). For very high-traffic endpoints a hybrid log-based approach may be preferable.
5. **Rate limit keys matter** — keying by `X-Forwarded-For` instead of the actual TCP connection IP allows trivial bypass by header spoofing (see the companion `rate-limit-bypass-tester` project).

## Further Reading

- [OWASP Testing for Insufficient Anti-Automation (OTG-AUTHN-010)](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6585 §4 — 429 Too Many Requests](https://www.rfc-editor.org/rfc/rfc6585)
- [Cloudflare: Rate Limiting Algorithm Comparison](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)
