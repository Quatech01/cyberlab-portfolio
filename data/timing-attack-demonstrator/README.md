# Timing Attack Demonstrator

A tool that detects timing side-channel vulnerabilities in token authentication endpoints — exposing how naive string comparison leaks secret information through response latency.

## What This Demonstrates

When a server compares a user-supplied token against a stored secret using a regular equality operator (`==`), it typically exits the loop as soon as it finds the first mismatching character. This means tokens that share a longer common prefix with the real secret take fractionally longer to reject than tokens that mismatch immediately.

An attacker can exploit this by measuring response latencies across many requests. By trying tokens that vary in their prefix, they can determine — character by character — what the correct secret looks like, without ever triggering an explicit "too many attempts" lockout. This is a **timing side-channel** or **timing oracle** attack.

The correct mitigation is to use a **constant-time comparison function** such as Python's `hmac.compare_digest` or Go's `subtle.ConstantTimeCompare`. These functions always examine every byte regardless of where a mismatch occurs, so the response time carries no information about the secret.

## How It Works

```
┌─────────────────────────────────────────────┐
│              FastAPI demo server            │
│                                             │
│  GET /api/check-naive?token=…               │
│    ↳ char-by-char comparison (VULNERABLE)   │
│      5ms sleep per matching character       │
│      amplifies the signal for demo clarity  │
│                                             │
│  GET /api/check-safe?token=…                │
│    ↳ hmac.compare_digest (SAFE)             │
│      constant time regardless of input      │
│                                             │
│  GET /api/secret-length                     │
│    ↳ returns length of the protected secret │
└─────────────────────────────────────────────┘
             ↑
┌─────────────────────────────────────────────┐
│               scanner tool                  │
│                                             │
│  1. Retrieve secret length                  │
│  2. Build three tokens with 0, ½, and       │
│     (n-1) prefix characters matching        │
│  3. Measure median latency for each token   │
│     on both endpoints (8 samples each)      │
│  4. Compute Pearson correlation between     │
│     prefix-match length and latency         │
│  5. Flag endpoint if r > 0.85 AND           │
│     timing delta > 20ms                     │
│  6. Emit structured JSON findings           │
└─────────────────────────────────────────────┘
```

The 5ms-per-character sleep in the naive endpoint is an intentional amplification for demonstration purposes — in production the same vulnerability exists at nanosecond scale and requires thousands of samples to confirm statistically.

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt

# Run the demo server
python main.py
# Server listens on http://127.0.0.1:3000

# In a second terminal — run the scanner
cd tool && pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the test suite
cd tests && pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/api/check-naive",
      "vulnerability_type": "timing_side_channel",
      "evidence": {
        "correlation": 0.999,
        "delta_ms": 74.3,
        "measurements": [
          { "prefix_match": 0,  "median_ms": 1.2  },
          { "prefix_match": 8,  "median_ms": 41.8 },
          { "prefix_match": 15, "median_ms": 75.5 }
        ]
      },
      "severity": "HIGH"
    }
  ],
  "summary": "/api/check-naive: VULNERABLE — timing correlation r=0.999, delta=74.3ms across prefix lengths | /api/check-safe: constant-time — no timing signal (safe)"
}
```

## Key Takeaways

- **Never use `==` to compare secrets.** Short-circuit evaluation turns a logical operation into a timing oracle.
- **`hmac.compare_digest` is the standard fix in Python.** It always processes every byte, eliminating per-character feedback.
- **The attack scales to any secret type** — API keys, HMAC signatures, session tokens, password reset codes.
- **Amplification helps detection but the risk is real at any scale.** Production attacks use statistical methods (e.g. t-tests over thousands of samples) to overcome network jitter.
- **Constant-time comparison alone is not enough** — the rest of the authentication flow (hashing, key derivation) must also be reviewed for timing leakage.

## Further Reading

- [OWASP: Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing)
- [Python docs: hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)
- [Remote Timing Attacks are Practical — Brumley & Boneh (2003)](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf)
