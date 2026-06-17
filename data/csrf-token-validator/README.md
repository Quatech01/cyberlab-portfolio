# CSRF Token Validator

A hands-on demonstration of Cross-Site Request Forgery (CSRF) attacks and the defences that stop them — synchronizer tokens, single-use rotation, and the `SameSite` cookie attribute.

---

## What This Demonstrates

**Cross-Site Request Forgery** tricks a user's browser into sending an authenticated request to a web application without the user's knowledge. Because the browser automatically attaches cookies to every matching request, a malicious page on `evil.com` can forge a funds-transfer form that posts to `bank.com` and the server has no native way to tell the difference from a legitimate submission.

This project shows three layers of defence:

| Defence | How it works | Endpoint |
|---------|-------------|----------|
| **Synchronizer token** | Server issues a secret random value that must accompany each state-changing request. A cross-origin attacker cannot read it (Same-Origin Policy). | `/transfer/protected` |
| **Token rotation** | Each token is single-use. Replaying a consumed token returns 403, preventing token-capture attacks. | `/transfer/protected` |
| **SameSite=Strict cookie** | Instructs the browser not to send the session cookie on any cross-site navigation, eliminating the cookie-based CSRF vector entirely. | `/account/secure-cookie` |

And the corresponding **vulnerable** versions — endpoints where none of these defences are in place.

---

## How It Works

```
┌─────────────────────────────────────┐
│  Demo Server (Express)              │
│                                     │
│  GET  /health                       │
│  GET  /csrf-token     ← issues token│
│  POST /transfer/vulnerable   ← VULN │
│  POST /transfer/protected    ← SAFE │
│  GET  /account/insecure-cookie ←VULN│
│  GET  /account/secure-cookie  ← SAFE│
└──────────────┬──────────────────────┘
               │ localhost only
┌──────────────▼──────────────────────┐
│  Scanner Tool (Node.js fetch)       │
│                                     │
│  1. POST /transfer/vulnerable       │
│     → succeeds without token (HIGH) │
│  2. POST /transfer/protected        │
│     → blocked without token         │
│  3. GET /csrf-token → use token     │
│     → succeeds, then replay fails   │
│  4. Check Set-Cookie SameSite attr  │
│     → missing = MEDIUM finding      │
│  5. Output structured JSON report   │
└─────────────────────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Tests (node:test)                  │
│  21 tests across 5 groups:          │
│  • server health                    │
│  • true positives                   │
│  • false positives (safe endpoints) │
│  • output format validation         │
│  • edge cases                       │
└─────────────────────────────────────┘
```

---

## Quick Start

```bash
# Install dependencies
cd server && npm install && cd ..

# Run the demo server
cd server && node index.js
# Server running on port 3000

# In a second terminal — run the scanner
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

---

## Example Output

```json
{
  "target": "http://localhost:3000",
  "session": "scanner-1718460000000-a3f9k2",
  "findings": [
    {
      "endpoint": "/transfer/vulnerable",
      "vulnerability": "MISSING_CSRF_PROTECTION",
      "evidence": "Cross-origin POST succeeded without any CSRF token (HTTP 200)",
      "severity": "HIGH"
    },
    {
      "endpoint": "/account/insecure-cookie",
      "vulnerability": "MISSING_SAMESITE_ATTRIBUTE",
      "evidence": "Set-Cookie header is missing SameSite — value: \"session=abc123; HttpOnly; Path=/\"",
      "severity": "MEDIUM"
    }
  ],
  "checks": {
    "vulnerable_transfer_flagged": true,
    "protected_transfer_blocked": true,
    "csrf_token_rotation_works": true,
    "insecure_cookie_flagged": true,
    "secure_cookie_passed": true
  },
  "summary": {
    "total_endpoints_tested": 5,
    "vulnerabilities_found": 2,
    "endpoints_tested": [
      "/transfer/vulnerable",
      "/transfer/protected (no token)",
      "/transfer/protected (with token)",
      "/transfer/protected (token replay)",
      "/account/insecure-cookie",
      "/account/secure-cookie"
    ]
  }
}
```

---

## Key Takeaways

- **Cookies alone are not authentication for state-changing requests.** The browser sends them automatically, so any page can trigger them cross-origin.
- **CSRF tokens work because attackers cannot read cross-origin responses.** The Same-Origin Policy prevents `evil.com` from fetching `bank.com/csrf-token` and reading the value.
- **Rotate tokens on every use.** A single-use token limits the damage if a token is leaked (e.g., via Referer header or browser history).
- **`SameSite=Strict` is now the simplest first-line defence**, but it is not universally supported in older browsers and does not protect against same-site subdomain attacks — so token validation remains important.
- **Referer-only validation is fragile** — some browsers suppress the Referer header, and some legitimate proxies strip it. It should be a supplement, never the primary control.

---

## Further Reading

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [RFC 6265 — HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265)
