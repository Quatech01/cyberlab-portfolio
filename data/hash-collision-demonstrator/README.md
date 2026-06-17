# Hash Collision Demonstrator

A hands-on tool that proves why MD5 and SHA-1 must never be used for security-critical hashing — and why SHA-256 is the minimum acceptable standard.

## What This Demonstrates

Hash functions are the backbone of password storage, file integrity checks, digital signatures, and certificate chains. Not all hash functions are equal:

- **MD5 (128-bit)** — Cryptographically broken. Wang et al. (2004) showed that two different messages can be engineered to produce the same MD5 hash. The birthday bound is ~2^64 operations, which is within reach of modern hardware.
- **SHA-1 (160-bit)** — Deprecated. The SHAttered attack (2017) produced the first practical SHA-1 collision using ~9.2 × 10^18 SHA-1 computations. Google demonstrated it with two PDF files sharing the same SHA-1 hash.
- **SHA-256 (256-bit)** — Current NIST recommendation. Birthday bound of ~2^128 operations; no practical attack is known.

This project provides a **live birthday-attack demonstration**: the server computes an actual collision on a 32-bit MD5 prefix at startup, proving the birthday principle with real numbers rather than theory.

## How It Works

```
┌─────────────────────────────────────────────────┐
│  Demo Server (Express)                          │
│                                                 │
│  GET  /health            — liveness probe       │
│  GET  /algorithms        — algorithm metadata   │
│  POST /hash              — hash any input       │
│  POST /verify-vulnerable — MD5 verification ⚠  │
│  POST /verify-safe       — SHA-256 verification │
│  GET  /birthday-demo     — live collision proof │
└─────────────────────────────────────────────────┘
         ▲
         │  HTTP
         ▼
┌─────────────────────────────────────────────────┐
│  Security Tool                                  │
│                                                 │
│  • Queries /algorithms — flags broken ones      │
│  • Tests /verify-vulnerable — flags MD5 use     │
│  • Fetches /birthday-demo — reports collision   │
│  • Tests /verify-safe — confirms no false pos.  │
│  • Outputs structured JSON + human summary      │
└─────────────────────────────────────────────────┘
         ▲
         │
         ▼
┌─────────────────────────────────────────────────┐
│  Test Suite (node:test)                         │
│                                                 │
│  Group 1 — Server health                        │
│  Group 2 — True positive detection              │
│  Group 3 — False positive checks (SHA-256)      │
│  Group 4 — Output format validation             │
│  Group 5 — Edge cases                           │
└─────────────────────────────────────────────────┘
```

The birthday attack at `/birthday-demo` works by hashing sequential strings (`probe-0`, `probe-1`, …) and storing their 32-bit MD5 prefixes. By the birthday paradox, a collision is expected after ~82,000 attempts — the server finds it in milliseconds and returns both colliding inputs.

## Quick Start

```bash
# Install dependencies
cd server && npm install && cd ..
cd tool  && npm install && cd ..
cd tests && npm install && cd ..

# Run the demo server (port 3000)
cd server && node index.js

# In another terminal — run the scanner
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "scanTime": "2026-05-25T10:00:00.000Z",
  "findings": [
    {
      "endpoint": "/algorithms",
      "vulnerability": "Cryptographically broken hash algorithm: MD5",
      "evidence": "MD5 (128-bit) — Practical collisions demonstrated by Wang et al. (2004)",
      "severity": "critical",
      "algorithm": "md5",
      "birthdayBound": 1.8446744073709552e+19
    },
    {
      "endpoint": "/algorithms",
      "vulnerability": "Deprecated hash algorithm in use: SHA1",
      "evidence": "SHA1 (160-bit) — SHAttered attack (2017) produced the first practical SHA-1 collision",
      "severity": "high",
      "algorithm": "sha1"
    },
    {
      "endpoint": "/verify-vulnerable",
      "vulnerability": "Hash verification uses MD5 — susceptible to collision forgery",
      "evidence": "MD5 is cryptographically broken — collisions are practical to compute",
      "severity": "critical",
      "algorithm": "md5"
    },
    {
      "endpoint": "/birthday-demo",
      "vulnerability": "Birthday attack collision proven on MD5 (32-bit prefix)",
      "evidence": "Two distinct inputs share MD5 prefix 3b4c5d6e after 71,203 attempts",
      "severity": "critical",
      "algorithm": "md5",
      "collisionProven": true
    }
  ],
  "summary": {
    "totalFindings": 4,
    "critical": 3,
    "high": 1,
    "collisionProven": true,
    "safeAlgorithmsDetected": ["sha256"]
  }
}
```

## Key Takeaways

1. **Never use MD5 for security purposes.** This includes password hashing, file integrity checks, digital signatures, or certificate fingerprints. It is broken by design — not by implementation.

2. **SHA-1 is deprecated.** NIST deprecated SHA-1 for most uses in 2011 and set a hard deadline. The SHAttered attack makes it unsuitable for anything requiring collision resistance.

3. **The birthday paradox is not theoretical.** With a 128-bit hash, an attacker only needs ~2^64 operations to find a collision — not 2^128. The birthday bound is always half the output bit width.

4. **SHA-256 is the current baseline.** For new systems, prefer SHA-256 or SHA-3. For passwords specifically, use bcrypt, scrypt, or Argon2 (slow-by-design hashes).

5. **Algorithm agility matters.** Design systems so the hash algorithm can be swapped out — what is secure today may be deprecated in ten years.

## Further Reading

- [NIST Transitioning Away from SHA-1](https://csrc.nist.gov/projects/hash-functions)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [SHAttered — First SHA-1 Collision (2017)](https://shattered.io/)
