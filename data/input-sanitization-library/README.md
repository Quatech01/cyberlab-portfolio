# Input Sanitization Library

A hands-on demonstration of three critical input sanitization techniques: HTML escaping, path normalization, and command injection prevention. Every concept is proved through automated tests that send real attack payloads to both vulnerable and hardened endpoints.

## What This Demonstrates

Raw user input is the root cause of XSS, path traversal, and command injection. This project implements a sanitization library (`server/sanitizer.js`) with three functions — `escapeHtml`, `normalizePath`, `sanitizeCommand` — and wires each one to a "safe" endpoint alongside an intentionally insecure "vulnerable" twin. The scanner tool then sends attack payloads to all six endpoints and reports which ones are susceptible.

**Vulnerability coverage:**

| Technique | Vulnerable pattern | Safe pattern |
|---|---|---|
| HTML escaping | `<p>Hello, ${input}!</p>` | `<p>Hello, ${escapeHtml(input)}!</p>` |
| Path normalization | `'./files/' + file` | `path.resolve` + `startsWith` guard |
| Command sanitization | `` `ping -c 1 ${input}` `` | reject any shell metacharacter |

## How It Works

```
server/index.js       — Express demo server with 6 endpoints (3 pairs)
server/sanitizer.js   — The sanitization library under test
tool/index.js         — Scanner: sends payloads, parses responses, outputs JSON
tests/test.js         — 18 node:test assertions across 5 groups
```

The test suite starts the server in-process on a random port, runs the scanner against it as a child process, and asserts both that vulnerable endpoints are detected and that safe endpoints produce no false positives.

## Quick Start

```bash
cd server && npm install
cd ../tool && npm install
cd ../tests && npm install

# Start the demo server (optional — tests start it automatically)
cd server && node index.js

# Run the scanner manually
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "timestamp": "2026-06-26T10:00:00.000Z",
  "findings": [
    {
      "endpoint": "/vuln/html",
      "vulnerability": "Cross-Site Scripting (XSS) — unescaped HTML output",
      "evidence": "Payload \"<script>alert(\"xss\")</script>\" reflected verbatim in output field",
      "severity": "HIGH"
    },
    {
      "endpoint": "/vuln/path",
      "vulnerability": "Path Traversal — unsanitized file parameter",
      "evidence": "Payload \"../../../etc/passwd\" produced: ./files/../../../etc/passwd",
      "severity": "HIGH"
    },
    {
      "endpoint": "/vuln/command",
      "vulnerability": "Command Injection — shell metacharacters accepted",
      "evidence": "Payload \"127.0.0.1; cat /etc/passwd\" embedded in: ping -c 1 127.0.0.1; cat /etc/passwd",
      "severity": "CRITICAL"
    }
  ],
  "summary": {
    "endpoints_scanned": 6,
    "vulnerable": 3,
    "safe": 3,
    "vulnerabilities_found": 3
  }
}
```

## Key Takeaways

- **Sanitize at the right layer**: escape HTML at the point of output, validate paths and commands at the point of input — where you apply sanitization matters as much as whether you apply it.
- **Allowlists beat denylists for commands**: rejecting any character not strictly needed is safer than enumerating every dangerous shell metacharacter.
- **`path.resolve` + `startsWith` is the idiomatic path guard**: URL-decoding, double-encoding, and null-byte tricks all collapse into the same normalized string, so a single boundary check handles them all.
- **HTML escaping is non-negotiable**: even strings that look benign at insert time may be rendered as HTML later; encode every user-controlled value before embedding.

## Further Reading

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
