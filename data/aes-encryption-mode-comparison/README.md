# AES Encryption Mode Comparison

A hands-on lab that shows why the choice of AES mode matters as much as the key itself. The project encrypts identical plaintexts with four different modes — ECB, CBC, CTR, and GCM — and lets you see the security differences directly in the ciphertext.

## What This Demonstrates

AES is a block cipher: it encrypts one 16-byte block at a time. A **mode of operation** decides how those blocks are chained together when your message is longer than 16 bytes.

| Mode | IV | Auth tag | Status | Why it matters |
|------|----|----------|--------|----------------|
| ECB  | No | No  | **Insecure**    | No IV means identical plaintext blocks → identical ciphertext blocks. An attacker can detect patterns without ever knowing the key. |
| CBC  | Yes | No | **Legacy**      | Random IV prevents the pattern problem, but the output is malleable. Padding oracle attacks (POODLE, BEAST) exploit this property. |
| CTR  | Yes | No | **Unauthenticated** | Converts AES into a stream cipher with no padding. Fast and parallelisable, but an attacker can flip ciphertext bits and the receiver cannot detect it. |
| GCM  | Yes | Yes | **Recommended** | Authenticated encryption: the 16-byte auth tag makes any tampering detectable. The current industry standard. |

The classic ECB weakness is visible with the naked eye when encrypting an image: identical pixel blocks appear as identical ciphertext blocks, so shapes remain recognisable. This project shows the same effect at the byte level.

## How It Works

```
┌──────────────────────────────────────────┐
│  Demo server  (Express, port 3000)       │
│                                          │
│  POST /api/vulnerable/encrypt  → ECB     │
│  POST /api/deprecated/encrypt  → CBC     │
│  POST /api/acceptable/encrypt  → CTR     │
│  POST /api/secure/encrypt      → GCM     │
│  GET  /demo/ecb-weakness                 │
│  GET  /health                            │
└───────────────┬──────────────────────────┘
                │  HTTP
┌───────────────▼──────────────────────────┐
│  Scanner tool  (tool/index.js)           │
│                                          │
│  1. Sends the same plaintext to all four │
│     encrypt endpoints — twice each.      │
│  2. Checks whether the ciphertext is     │
│     deterministic (ECB flaw).            │
│  3. Checks for IV and authTag fields.    │
│  4. Fetches /demo/ecb-weakness and       │
│     confirms identical blocks appear in  │
│     ECB output but not in GCM output.   │
│  5. Classifies each mode and outputs     │
│     structured JSON + human summary.     │
└──────────────────────────────────────────┘
```

The test suite starts the server on a random port, runs the tool against it, and asserts the expected severity ratings, false-positive absence for GCM, output format correctness, and graceful failure handling.

## Quick Start

```bash
# 1. Install dependencies
cd server && npm install && cd ..

# 2. Start the demo server
node server/index.js

# 3. Run the scanner (in a separate terminal)
node tool/index.js --target http://localhost:3000

# 4. Run the automated test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "timestamp": "2026-06-16T09:00:00.000Z",
  "findings": [
    {
      "endpoint": "/api/vulnerable/encrypt",
      "mode": "ECB",
      "severity": "HIGH",
      "vulnerable": true,
      "uses_iv": false,
      "authenticated": false,
      "deterministic": true,
      "issues": [
        "No IV — identical plaintext always produces identical ciphertext, leaking data patterns"
      ],
      "evidence": "Same plaintext encrypted twice produced identical ciphertext: 3f2b1a..."
    },
    {
      "endpoint": "/api/deprecated/encrypt",
      "mode": "CBC",
      "severity": "MEDIUM",
      "vulnerable": true,
      "uses_iv": true,
      "authenticated": false,
      "deterministic": false,
      "issues": [
        "No authentication tag — susceptible to padding oracle attacks and ciphertext bit-flipping"
      ]
    },
    {
      "endpoint": "/api/acceptable/encrypt",
      "mode": "CTR",
      "severity": "LOW",
      "vulnerable": false,
      "uses_iv": true,
      "authenticated": false,
      "deterministic": false,
      "issues": [
        "No authentication tag — ciphertext integrity is not verified (unauthenticated encryption)"
      ]
    },
    {
      "endpoint": "/api/secure/encrypt",
      "mode": "GCM",
      "severity": "NONE",
      "vulnerable": false,
      "uses_iv": true,
      "authenticated": true,
      "deterministic": false,
      "issues": []
    }
  ],
  "pattern_test": {
    "endpoint": "/demo/ecb-weakness",
    "ecb_blocks_identical": true,
    "evidence": "ECB block1 === block2 (3f2b1a...): repeated plaintext blocks reveal structure"
  },
  "summary": {
    "total_modes_tested": 4,
    "vulnerable_modes": 2,
    "secure_modes": 1,
    "risk_score": "HIGH",
    "recommendation": "Use AES-GCM (authenticated encryption) for all new implementations"
  }
}
```

## Key Takeaways

1. **ECB is never acceptable** for encrypting more than one block of data. Its determinism leaks structural information about the plaintext even to an observer who cannot read it.
2. **CBC is not broken, but it is risky** without careful padding validation. Modern protocols avoid it in favour of authenticated modes.
3. **Authenticated encryption (AEAD) is the baseline** for any real system. AES-GCM combines confidentiality and integrity in a single pass — if the auth tag check fails, the message is discarded before it is ever decrypted.
4. **The IV must be unpredictable and unique per message.** Reusing an IV with the same key under CTR or GCM is catastrophic — it allows an attacker to XOR ciphertexts and recover the plaintext XOR.
5. **Shorter is not simpler.** AES-GCM is one function call in every modern crypto library. There is no practical reason to use ECB or bare CBC for new code.

## Further Reading

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-38D — Recommendation for GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Node.js crypto module documentation](https://nodejs.org/api/crypto.html)
