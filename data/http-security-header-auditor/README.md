# HTTP Security Header Auditor

Scans HTTP response headers for security best practices and grades each endpoint A–F based on which protective headers are present or missing.

## What This Demonstrates

Modern browsers expose a set of HTTP response headers that let servers opt in to defensive browser behaviours — preventing clickjacking, MIME-type sniffing, cross-site scripting, and information leakage. When these headers are absent, the browser's default, permissive behaviour applies and many classes of client-side attack become trivially exploitable.

This project shows what those headers look like in practice, what happens when they are omitted, and how a scanner can mechanically verify their presence across every endpoint in a service.

The six headers audited are:

| Header | Weight | What it prevents |
|---|---|---|
| `Strict-Transport-Security` | 2 | SSL stripping / HTTP downgrade attacks |
| `X-Content-Type-Options` | 1 | MIME-type sniffing attacks |
| `X-Frame-Options` | 1 | Clickjacking via `<iframe>` embedding |
| `Content-Security-Policy` | 2 | XSS and data injection via inline scripts/styles |
| `Referrer-Policy` | 1 | Referrer header leaking sensitive URL parameters |
| `Permissions-Policy` | 1 | Unauthorised use of camera, microphone, geolocation |

Headers are weighted so that the two most impactful (HSTS and CSP) count double, giving a maximum score of 8.

## How It Works

```
server/   – Express demo with three routes at different security levels
tool/     – Scanner using node:http; grades each endpoint A–F
tests/    – node:test suite with 23 tests across 5 groups
```

`GET /headers/none` sets no security headers at all → grade **F**, severity **HIGH**.  
`GET /headers/partial` sets only `X-Content-Type-Options` and `X-Frame-Options` → grade **C**, severity **MEDIUM**.  
`GET /headers/full` sets all six recommended headers → grade **A**, not flagged.

The tool connects to the demo server, reads the response headers of each endpoint, computes a weighted score, converts the score to a letter grade, and emits findings only for endpoints that fall below grade A.

## Quick Start

```bash
# Install server dependencies
cd server && npm install && cd ..

# Run the demo server (stays running in the background)
node server/index.js &

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
      "endpoint": "/headers/none",
      "vulnerability_type": "missing_security_headers",
      "evidence": {
        "grade": "F",
        "missing_headers": [
          "strict-transport-security",
          "x-content-type-options",
          "x-frame-options",
          "content-security-policy",
          "referrer-policy",
          "permissions-policy"
        ],
        "present_headers": []
      },
      "severity": "HIGH"
    },
    {
      "endpoint": "/headers/partial",
      "vulnerability_type": "missing_security_headers",
      "evidence": {
        "grade": "C",
        "missing_headers": [
          "strict-transport-security",
          "content-security-policy",
          "referrer-policy",
          "permissions-policy"
        ],
        "present_headers": [
          "x-content-type-options",
          "x-frame-options"
        ]
      },
      "severity": "MEDIUM"
    }
  ],
  "summary": {
    "endpoints_scanned": 3,
    "total_findings": 2,
    "grades": [
      { "endpoint": "/headers/none",    "grade": "F" },
      { "endpoint": "/headers/partial", "grade": "C" },
      { "endpoint": "/headers/full",    "grade": "A" }
    ]
  }
}
```

## Key Takeaways

- **Absent headers are not neutral.** Each missing header re-enables a class of browser attack that the header was designed to block.
- **HSTS and CSP carry the most weight.** HSTS prevents downgrade attacks even after a user types a bare `http://` URL; CSP is the primary control against XSS execution.
- **Grading creates actionable priority.** Grade F endpoints (zero headers) are immediate remediation targets; grade B/C endpoints are technical debt to schedule.
- **Header scanning belongs in CI.** A scanner like this can run on every deploy to catch regressions before they reach production.

## Further Reading

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN: HTTP security headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [Mozilla Observatory — header scoring methodology](https://observatory.mozilla.org/faq/)
