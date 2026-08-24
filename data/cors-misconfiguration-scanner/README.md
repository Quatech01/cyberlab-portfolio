# CORS Misconfiguration Scanner

Detects dangerous Cross-Origin Resource Sharing policies that allow attacker-controlled pages to silently read authenticated API responses.

## What This Demonstrates

Cross-Origin Resource Sharing (CORS) is the browser mechanism that controls which origins can read responses from a server. A misconfigured CORS policy can completely undermine your authentication layer — even if you use HTTPS, JWT tokens, and HttpOnly cookies, a bad CORS policy lets any attacker web page silently call your API and steal the response.

Three specific vulnerabilities are demonstrated:

**1. Wildcard origin (`Access-Control-Allow-Origin: *`)**
Harmless for truly public, unauthenticated endpoints. Dangerous the moment the endpoint gains any form of authentication, because the wildcard cannot be combined with `Access-Control-Allow-Credentials: true` in a browser — but developers sometimes remove the credential requirement to "fix" the browser error, inadvertently opening a wider hole.

**2. Reflected origin with credentials**
The server reads the incoming `Origin` header and echoes it back verbatim in `Access-Control-Allow-Origin`, combined with `Access-Control-Allow-Credentials: true`. Any origin — including `http://evil.attacker.com` — receives permission to make credentialed cross-origin requests and read the full response. This is the most dangerous CORS misconfiguration and is commonly found in APIs that tried to support multiple legitimate origins but implemented the logic incorrectly.

**3. Null origin with credentials**
Sandboxed iframes (created with `<iframe sandbox>`, using `data:` URIs, or `srcdoc`) send `Origin: null`. An API that explicitly allows `null` with credentials permits attacker-controlled sandboxed frames to read authenticated responses — a subtle vector that bypasses many CORS audits.

## How It Works

```
server/         FastAPI demo server with four endpoint groups
  main.py         /api/unsafe/data    — wildcard CORS (MEDIUM)
                  /api/leak/profile   — reflected origin + credentials (HIGH)
                  /api/null/upload    — null origin + credentials (HIGH)
                  /api/safe/account   — strict allowlist (no finding)

tool/           CORS scanner
  main.py         Probes each endpoint with attacker and null origins
                  Reports structured JSON findings with severity ratings

tests/          pytest suite (the gate before any GitHub push)
  test.py         6 groups × multiple assertions = 35 tests
```

The test suite proves three things: the vulnerable endpoints are correctly detected, the safe endpoint produces no false positive, and the tool handles unreachable servers without crashing.

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt

# Run the demo server
python main.py
# Server starts on http://127.0.0.1:3000

# In a second terminal — run the scanner
cd tool && pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the full test suite
cd tests && pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/api/unsafe/data",
      "vulnerability_type": "CORS_WILDCARD",
      "evidence": "Access-Control-Allow-Origin: * — any origin can read this response. Harmless for fully public data, but becomes critical if authentication is ever added.",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/api/leak/profile",
      "vulnerability_type": "CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS",
      "evidence": "Access-Control-Allow-Origin: http://evil.attacker.com (reflected), Access-Control-Allow-Credentials: true — any attacker page can make credentialed cross-origin requests and read the full response including session cookies.",
      "severity": "HIGH"
    },
    {
      "endpoint": "/api/null/upload",
      "vulnerability_type": "CORS_NULL_ORIGIN_WITH_CREDENTIALS",
      "evidence": "Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true — sandboxed iframes (data: URIs, srcdoc) send Origin: null and can therefore read credentialed responses.",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 3 CORS misconfiguration(s) — 2 HIGH severity. Reflected-origin + credentials and null-origin + credentials allow attacker-controlled pages to silently read authenticated API responses."
}
```

## Key Takeaways

- **Never reflect the incoming `Origin` header back unconditionally.** Maintain an explicit allowlist of trusted origins and only echo the header when the request's origin is on the list.
- **`Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` cannot coexist** — browsers reject this combination. If you see code that removes the `*` to "fix" the error and replaces it with a reflected origin, that is the misconfiguration.
- **`null` is not a safe origin.** Treating `null` as a trustworthy origin permits sandboxed iframe attacks. Allowlists should never include the string `"null"`.
- **Add `Vary: Origin`** when your CORS policy is origin-dependent. Without it, a CDN may cache a response from a trusted origin and serve it without CORS headers to subsequent requests from other origins, causing legitimate cross-origin requests to fail.
- **CORS is a browser control, not a server security boundary.** curl and httpx can bypass it freely — CORS only restricts browser-initiated cross-origin reads. Authentication and authorisation must still be enforced server-side.

## Further Reading

- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)
- [Fetch Living Standard — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [PortSwigger Web Academy — CORS vulnerabilities](https://portswigger.net/web-security/cors)
