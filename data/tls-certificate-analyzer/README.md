# TLS Certificate Analyzer

Fetches X.509 certificates from a demo server over HTTP and flags common PKI security misconfigurations: expired certificates, self-signed issuers, undersized RSA keys, and missing Subject Alternative Names.

## What This Demonstrates

Every TLS connection you make begins with a certificate handshake. The server presents an X.509 certificate that proves its identity, and your client decides whether to trust it. Misconfigured certificates silently undermine that trust:

| Issue | Why it matters |
|---|---|
| **Expired certificate** | The validity period is the primary time-bound trust signal. An expired cert may indicate an abandoned service or a neglected renewal process. Browsers hard-reject expired certs. |
| **Self-signed certificate** | A self-signed cert can be forged by anyone. Without a trusted Certificate Authority (CA) in the chain, the client cannot verify the server's identity — a man-in-the-middle can present their own self-signed cert instead. |
| **Weak RSA key (< 2048 bits)** | NIST SP 800-131A (2015) deprecated 1024-bit RSA because a well-funded adversary can factor such keys. All keys issued after 2010 should be at least 2048 bits. |
| **Missing Subject Alternative Names (SAN)** | RFC 2818 §3.1 requires the server hostname to appear in the SAN extension. The Common Name (CN) field was deprecated for hostname validation in Chrome 58 (2017). Cert without SANs will be rejected by modern browsers. |

## How It Works

```
server/main.py       ← FastAPI server (generates 4 X.509 certs at startup)
    │
    ├── GET /health              → {"status": "ok"}
    ├── GET /certificates        → lists cert IDs + labels
    └── GET /certificates/{id}  → returns PEM data for that cert

tool/main.py         ← analyzer: fetches each PEM, parses with cryptography, flags issues
tests/test.py        ← pytest: 37 tests across health, true/false positives, format, edge cases
```

The server uses Python's `cryptography` library to generate four certificates at startup — no pre-baked PEM files, no OpenSSL subprocess:

- `expired` — signed by the local CA but expired 30 days ago
- `self_signed` — signed by its own key, no Subject Alternative Names
- `weak_key` — 1024-bit RSA key (below the 2048-bit minimum)
- `valid` — 2048-bit RSA, CA-signed, full SAN, 364-day validity

The tool fetches `/certificates` to discover all cert IDs, then fetches each PEM, parses it with `cryptography.x509`, and runs four checks. The `valid` cert produces zero findings.

## Quick Start

**Requirements:** Python 3.10+

```bash
# Install dependencies
cd server && pip install -r requirements.txt
cd ../tool && pip install -r requirements.txt

# Run the demo server
cd server && python main.py
# Server running at http://127.0.0.1:3000

# Run the analyzer (separate terminal)
cd tool && python main.py --target http://localhost:3000

# Run tests
cd tests && pip install -r requirements.txt && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "http://localhost:3000/certificates/expired",
      "vulnerability_type": "EXPIRED_CERTIFICATE",
      "evidence": "Certificate expired 30 day(s) ago on 2026-07-05",
      "severity": "HIGH"
    },
    {
      "endpoint": "http://localhost:3000/certificates/self_signed",
      "vulnerability_type": "SELF_SIGNED_CERTIFICATE",
      "evidence": "Issuer and subject are identical: 'CN=selfsigned.example.local'. Browsers and clients reject self-signed certificates as untrusted.",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "http://localhost:3000/certificates/self_signed",
      "vulnerability_type": "MISSING_SUBJECT_ALTERNATIVE_NAME",
      "evidence": "Certificate has no Subject Alternative Names (SAN) extension. RFC 2818 §3.1 requires SANs; CN-only matching was deprecated in Chrome 58 (2017).",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "http://localhost:3000/certificates/weak_key",
      "vulnerability_type": "WEAK_RSA_KEY",
      "evidence": "RSA key is 1024 bits. The minimum recommended size is 2048 bits (NIST SP 800-131A, 2015).",
      "severity": "HIGH"
    }
  ],
  "summary": "Analyzed 4 certificate(s). Found 4 issue(s): 2 HIGH, 2 MEDIUM."
}
```

## Key Takeaways

1. **Certificate expiry monitoring is ops-critical.** A certificate that expires unexpectedly takes a service offline for all HTTPS clients. Automate renewal (ACME / Let's Encrypt) and monitor expiry with alerts at 30 and 7 days.

2. **Self-signed certificates are only safe in completely closed systems.** For any user-facing or inter-service TLS, use a certificate from a trusted CA or an internal PKI with roots deployed to all clients.

3. **Key size affects how long a certificate is safe to use.** A 1024-bit RSA key could be factored today by a nation-state; a 2048-bit key provides safety until at least 2030. For new issuance, prefer 3072-bit RSA or ECDSA P-256 (equivalent strength to 3072-bit RSA, smaller and faster).

4. **SANs are mandatory, not optional.** Every certificate must list its hostnames in the SAN extension. The CN field is ignored for hostname validation in all modern TLS stacks. A cert without SANs will fail validation regardless of whether the CN matches.

5. **Parse, don't just display.** Certificate scanners that simply check whether HTTPS connects miss the detail. Parsing the PEM with a full X.509 library lets you inspect every field — key size, signature algorithm, extension presence — and produce actionable findings.

## Further Reading

- [NIST SP 800-131A Rev 2 — Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [RFC 5280 — Internet X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 2818 — HTTP Over TLS (SAN hostname validation §3.1)](https://datatracker.ietf.org/doc/html/rfc2818#section-3.1)
