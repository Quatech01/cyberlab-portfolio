# Brute Force Rate Limiter Demo

A hands-on demonstration of brute-force login protection. Two Express endpoints
sit side by side — one open to unlimited password guessing, one enforcing a
5-attempt lockout — and an automated scanner proves the difference.

---

## What This Demonstrates

**Brute-force attacks** work by automating credential guessing: try thousands
of passwords until one succeeds. Without rate limiting, an attacker sends
requests as fast as the network allows. The defence is simple: track consecutive
failures per client and stop responding normally after a threshold.

Key concepts covered:

- **Rate limiting vs. account lockout** — per-IP throttling slows guessing;
  lockout halts it entirely.
- **Sliding vs. fixed window** — this demo uses a fixed lockout window that
  resets on a successful login.
- **False positive risk** — too aggressive a lockout enables denial-of-service
  against legitimate users; the right threshold and lockout duration matter.
- **IP-based vs. username-based tracking** — tracking by IP stops distributed
  attacks; tracking by username prevents locking out one user from many IPs.

---

## How It Works

```
┌─────────────────────────┐          ┌──────────────────────────────┐
│  Demo server            │          │  Scanner tool                │
│  POST /login/vulnerable │◄─────────│  Sends 10 wrong passwords    │
│  (no rate limiting)     │  10×401  │  to each endpoint, counts    │
│                         │          │  when (if) 429 is returned   │
│  POST /login/protected  │◄─────────│                              │
│  (5-attempt lockout)    │  5×401   │  Reports findings as JSON    │
│                         │  then    │  with severity + evidence    │
│  POST /reset-lockout    │  429     │                              │
│  GET  /lockout-status   │          └──────────────────────────────┘
└─────────────────────────┘
```

The test suite starts the server on a random port, runs both manual HTTP probes
and the scanner, and verifies: (1) the vulnerable endpoint never throttles,
(2) the protected endpoint locks out within 6 attempts, (3) the scanner reports
exactly the right findings — no false positives on the safe endpoint.

---

## Quick Start

```bash
# Install dependencies
cd server && npm install
cd ../tool && npm install
cd ../tests && npm install

# Run the demo server
cd server && npm start
# Server running on port 3000

# Run the scanner (in a second terminal)
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

---

## Example Output

```json
{
  "target": "http://localhost:3000",
  "scannedAt": "2026-05-25T12:00:00.000Z",
  "findings": [
    {
      "endpoint": "/login/vulnerable",
      "vulnerability": "Missing Rate Limiting",
      "evidence": "Completed 10 consecutive failed login attempts without triggering any rate limit or lockout.",
      "severity": "HIGH",
      "detail": "This endpoint accepts an unlimited number of failed login attempts, enabling automated password guessing (brute-force) attacks."
    }
  ],
  "securePaths": [
    {
      "endpoint": "/login/protected",
      "protection": "Rate Limiting Active",
      "detail": "Rate limit triggered after 5 attempt(s). Subsequent requests correctly receive HTTP 429."
    }
  ],
  "summary": {
    "endpointsTested": 2,
    "vulnerableEndpoints": 1,
    "rateLimitingDetected": true,
    "recommendation": "Implement rate limiting on ALL authentication endpoints. Use a sliding-window counter keyed by IP (and optionally by username) with exponential backoff or a fixed lockout period after threshold failures."
  }
}
```

---

## Key Takeaways

1. **Every login endpoint needs rate limiting.** A single unprotected path
   undermines an otherwise well-secured application.
2. **Track failures by both IP and username.** IP-only tracking is bypassed
   by rotating proxies; username-only tracking enables DoS against a target
   account from many IPs.
3. **Communicate clearly to legitimate users.** Return `Retry-After` headers
   with 429 responses so users know how long to wait.
4. **Reset the counter on success.** A successful login proves the user knows
   the password; resetting the failure count avoids locking them out later.
5. **Combine rate limiting with monitoring.** Lockouts slow attackers; alerts
   on repeated lockouts help you detect and respond to ongoing attacks.

---

## Further Reading

- [OWASP Testing for Weak Lockout Mechanism (WSTG-ATHN-03)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
