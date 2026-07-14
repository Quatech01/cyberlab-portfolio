# Open Redirect Checker

Scans web endpoints for open redirect vulnerabilities — cases where a server accepts a user-supplied URL and redirects without validating the destination against an allowlist.

## What This Demonstrates

An **open redirect** occurs when an application accepts an attacker-controlled URL via a parameter (e.g. `?url=`, `?returnTo=`, `?next=`) and issues an HTTP redirect to that URL without first checking whether the destination is trusted. Attackers abuse this to craft legitimate-looking links (using a trusted domain in the URL bar) that silently forward victims to phishing pages, credential harvesters, or malware downloads.

Three patterns are shown:
1. **No validation** — the server redirects to whatever URL it receives.
2. **Weak substring check** — the server looks for a trusted domain *anywhere* in the URL (including query strings), so an attacker embeds the trusted name in their own URL to bypass the check.
3. **Allowlist validation** — the server parses the full URL, extracts the origin, and compares it against a strict list. Unrecognised origins are rejected with HTTP 400.

## How It Works

```
open-redirect-checker/
├── server/      Express app with 4 redirect endpoints at different security levels
├── tool/        Scanner that probes each endpoint with attack payloads
└── tests/       27 node:test tests covering all 5 groups
```

**Server endpoints:**
| Path | Security level | Behaviour |
|---|---|---|
| `/redirect/unsafe` | Vulnerable | Redirects to any URL — no validation |
| `/redirect/partial` | Vulnerable | Checks if the URL *contains* a trusted domain — bypassable |
| `/redirect/safe` | Safe | Parses URL and checks origin against an allowlist |
| `/login?returnTo=` | Safe | Only accepts relative paths; rejects `https://` and `//` prefixes |

**Tool logic:**
1. Verifies the server is reachable (`/health`).
2. Sends external attacker URLs to `/redirect/unsafe` — expects 301/302.
3. Sends a bypass payload to `/redirect/partial` — trusted domain in query string, evil host as the actual destination.
4. Sends an absolute URL to `/login` — expects rejection (400).
5. Probes `/redirect/safe` with an external URL — must NOT follow the redirect.

## Quick Start

```bash
# Install dependencies
cd server && npm install && cd ..
cd tool && npm install && cd ..
cd tests && npm install && cd ..

# Run the demo server
node server/index.js

# Run the scanner
node tool/index.js --target http://localhost:3000

# Run all tests
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/redirect/unsafe",
      "vulnerability_type": "open_redirect",
      "evidence": "HTTP 302 Location: https://evil.example.com/phish",
      "severity": "HIGH",
      "payload": "https://evil.example.com/phish"
    },
    {
      "endpoint": "/redirect/partial",
      "vulnerability_type": "open_redirect_weak_validation",
      "evidence": "Bypass succeeded: payload contained trusted domain in query string. HTTP 302",
      "severity": "HIGH",
      "payload": "https://evil-trusted.example.org/?q=trusted.example.org"
    }
  ],
  "summary": "Detected 2 open redirect vulnerability/vulnerabilities. Unvalidated redirect endpoints allow attackers to craft phishing links that appear to originate from a trusted domain."
}
```

## Key Takeaways

- **Never use user-supplied URLs as redirect destinations without strict validation.** Even a single unvalidated redirect parameter is enough to weaponise your domain for phishing.
- **Substring / contains checks are bypassable.** Attackers embed the trusted domain in their URL's path, query string, or fragment. Parse the full URL and compare the *origin* (scheme + host + port) against a strict allowlist.
- **For internal navigation, prefer relative paths only.** Reject any value starting with `https://`, `http://`, or `//` — relative paths can't point off-domain.
- **Allowlist, not blocklist.** Attempting to block `evil.com` fails when attackers register `trusteddomain.evil.com` or use URL encoding tricks.
- **The Location header is the evidence.** When a scanner follows redirects automatically it may miss the issue; check the raw 301/302 response instead.

## Further Reading

- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [RFC 7231 §6.4 — HTTP Redirection](https://datatracker.ietf.org/doc/html/rfc7231#section-6.4)
