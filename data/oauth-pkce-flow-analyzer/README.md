# OAuth 2.0 PKCE Flow Analyzer

A hands-on demonstration of OAuth 2.0 authorization code vulnerabilities and how PKCE (Proof Key for Code Exchange) closes them.

## What This Demonstrates

OAuth 2.0's authorization code flow was originally designed for server-side applications that could keep a client secret. Public clients — single-page apps and mobile apps — cannot keep secrets, which creates a dangerous gap: if an attacker intercepts the authorization code (via a malicious redirect, a referrer leak, or a browser history snoop), they can exchange it for an access token themselves.

PKCE (RFC 7636) solves this by binding the authorization code to a secret known only to the legitimate client. The client generates a random `code_verifier`, hashes it to produce a `code_challenge`, sends the challenge at authorization time, then proves ownership by sending the verifier at token exchange time. Even if an attacker steals the code, they cannot exchange it without the verifier.

This project exposes two common PKCE misconfigurations:

1. **Missing PKCE enforcement** — the token endpoint issues tokens without requiring a `code_verifier`, making the whole PKCE mechanism voluntary and therefore useless.
2. **Unvalidated redirect_uri** — the authorization endpoint accepts any redirect URI without checking against a registered allowlist, letting attackers route authorization codes to their own endpoints.

## How It Works

```
server/   Express demo server with two OAuth flows:
            /auth/authorize        — vulnerable (no PKCE, any redirect_uri)
            /auth/token            — vulnerable (no code_verifier check)
            /auth/secure/authorize — safe (PKCE required, redirect_uri allowlisted)
            /auth/secure/token     — safe (verifies SHA-256(code_verifier) == code_challenge)
            /api/profile           — Bearer-token protected resource
            /health                — health check

tool/     Scanner that probes the vulnerable endpoints:
            - Obtains an auth code without a code_challenge
            - Exchanges it without a code_verifier → reports missing_pkce_verification
            - Requests authorization with an unregistered redirect_uri → reports unvalidated_redirect_uri

tests/    22 node:test assertions covering:
            - Server health and startup
            - True positive detection (scanner catches both vulnerabilities)
            - False positive suppression (scanner ignores the safe endpoints)
            - Output format (required JSON fields present)
            - Edge cases (unreachable server, replay prevention, invalid tokens)
```

## Quick Start

```bash
# Install server dependencies
cd server && npm install && cd ..

# Run the demo server
node server/index.js

# In another terminal — run the scanner
node tool/index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm install && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/auth/token",
      "vulnerability_type": "missing_pkce_verification",
      "evidence": "Server issued an access token without a code_verifier — any party that intercepts the authorization code can exchange it for tokens without knowledge of the original verifier secret",
      "severity": "HIGH"
    },
    {
      "endpoint": "/auth/authorize",
      "vulnerability_type": "unvalidated_redirect_uri",
      "evidence": "Server accepted an unregistered redirect_uri (http://evil.example.com/steal-code) and directed the authorization code to it — enables authorization code theft via crafted phishing links",
      "severity": "HIGH"
    }
  ],
  "summary": {
    "checks_run": 2,
    "vulnerabilities_found": 2,
    "high_severity": 2
  }
}
```

## Key Takeaways

- **PKCE only works if the server enforces it.** A server that accepts token requests without a `code_verifier` provides no protection even if clients send one.
- **redirect_uri must be validated against a pre-registered allowlist.** RFC 6749 requires exact string matching — prefix matching or partial validation is insufficient.
- **Authorization codes should be short-lived and single-use.** The safe endpoint deletes each code immediately after exchange, preventing replay attacks.
- **Public clients must always use PKCE.** The OAuth 2.1 draft makes PKCE mandatory for all clients, not just public ones.

## Further Reading

- [RFC 7636 — PKCE for OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636)
- [OWASP — Testing for OAuth Weaknesses](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)
- [OAuth 2.0 Security Best Current Practice (BCP 240)](https://www.rfc-editor.org/rfc/rfc9700)
