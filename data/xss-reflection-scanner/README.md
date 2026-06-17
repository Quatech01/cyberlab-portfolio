# XSS Reflection Scanner

A command-line tool that detects reflected cross-site scripting (XSS) vulnerabilities by injecting payloads into URL parameters and checking whether they appear in the response without HTML encoding.

## What This Demonstrates

**Reflected XSS** occurs when user-supplied input is embedded directly into an HTML response without sanitization. An attacker crafts a URL containing a script payload; when a victim clicks the link, the injected script executes in their browser under the site's origin.

This project shows three defences side-by-side:

| Endpoint | Defence | Risk |
|---|---|---|
| `/search` | None | HIGH — payload executes |
| `/search-escaped` | HTML entity encoding | None — payload rendered as text |
| `/search-csp` | Content-Security-Policy: script-src 'none' | MEDIUM — payload in DOM, blocked by CSP |

The key insight: **output encoding is the correct fix**. CSP is a useful secondary control but not a substitute — a misconfigured or bypassable CSP still leaves the reflection in the page.

## How It Works

```
server/index.js   — Express app with three search endpoints at different security levels
tool/index.js     — Scanner that fires XSS payloads and checks raw reflection in responses
tests/test.js     — node:test suite that starts the server in-process and drives the tool
```

The tool:
1. Verifies the target is reachable via `GET /health`
2. For each endpoint, sends five canonical XSS payloads as query parameters
3. Checks whether the unencoded payload string appears in the response body
4. If it does, creates a finding with severity HIGH (no CSP) or MEDIUM (CSP present)
5. Emits structured JSON to stdout; a human-readable summary goes to stderr

## Quick Start

```bash
# Install server deps
cd server && npm install && cd ..

# Start demo server (port 3000)
cd server && node index.js &

# Run scanner against it
cd tool && node index.js --target http://localhost:3000

# Run full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "scanned_at": "2026-05-26T12:00:00.000Z",
  "endpoints_tested": ["/search", "/search-escaped", "/search-csp"],
  "findings": [
    {
      "endpoint": "/search",
      "vulnerability": "XSS Reflection",
      "evidence": "Payload reflected without HTML encoding: <script>alert(1)</script>",
      "severity": "HIGH",
      "payload": "<script>alert(1)</script>",
      "csp_present": false
    },
    {
      "endpoint": "/search-csp",
      "vulnerability": "XSS Reflection",
      "evidence": "Payload reflected without HTML encoding: <script>alert(1)</script>",
      "severity": "MEDIUM",
      "payload": "<script>alert(1)</script>",
      "csp_present": true
    }
  ],
  "summary": "Found 2 XSS reflection issue(s) across 3 endpoints"
}
```

## Key Takeaways

- **Always HTML-encode user input before inserting it into HTML context.** Use a library (`he`, `DOMPurify`) or your framework's built-in escaping rather than rolling your own.
- **CSP is defence-in-depth, not a primary fix.** It can prevent execution even when the reflection exists, but a misconfigured policy or a bypass leaves users exposed.
- **Reflected XSS requires the victim to follow a malicious link.** Stored XSS (where the payload is persisted) is more dangerous because no crafted link is needed.
- **Context matters.** The same input needs different encoding depending on whether it's placed in HTML text, an HTML attribute, JavaScript, or a URL.

## Further Reading

- [OWASP: Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
