# Password Hashing Benchmark

A hands-on comparison of password hashing algorithms — SHA-256, bcrypt, scrypt, and argon2id — demonstrating why fast cryptographic hashes are dangerously unsuitable for password storage.

## What This Demonstrates

Most developers know to "hash passwords before storing them," but the choice of algorithm matters enormously. A cryptographic hash like SHA-256 is intentionally fast — it is designed to process gigabytes of data quickly. That speed becomes a liability for passwords: a modern GPU can compute over **10 billion SHA-256 hashes per second**, turning a stolen hash database into a crackable one within hours.

Purpose-built password hashing functions work differently:

| Algorithm | Time per hash | Mechanism | GPU-resistant? |
|-----------|---------------|-----------|----------------|
| SHA-256   | ~0.002 ms     | Fixed computation | No — billions/sec on GPU |
| bcrypt    | ~300 ms       | Adaptive Feistel cipher | Yes — serial algorithm |
| scrypt    | ~40 ms        | Memory-hard KDF | Yes — 128 MiB RAM required |
| argon2id  | ~30 ms        | Memory+time-hard | Yes — PHC winner, side-channel safe |

The benchmark tool probes a demo server to measure these timings, attempts a dictionary attack against each algorithm's stored hash, and flags any algorithm that is dangerously fast.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Demo Server (FastAPI, port 3000)                        │
│                                                          │
│  /hashes     — pre-seeded hash of "password123" for     │
│                each algorithm (SHA-256, bcrypt, scrypt,  │
│                argon2id)                                 │
│  /benchmark  — times one hash per algorithm; marks       │
│                SHA-256 safe:false, the rest safe:true    │
│  /crack      — tries a wordlist against a stored hash    │
│  /verify     — verifies a password against a stored hash │
└──────────────────┬──────────────────────────────────────┘
                   │ HTTP
┌──────────────────▼──────────────────────────────────────┐
│  Scanner Tool (tool/main.py)                             │
│                                                          │
│  1. GET /benchmark — identify unsafe algorithms          │
│  2. GET /hashes    — fetch stored hashes                 │
│  3. POST /crack    — dictionary attack on unsafe hashes  │
│  4. Report JSON findings + human stderr summary          │
└─────────────────────────────────────────────────────────┘
```

The test suite starts an in-process server on a random port, runs the tool as a subprocess, and validates both true-positive detection (SHA-256 flagged and cracked) and false-positive suppression (bcrypt/scrypt/argon2 not flagged).

## Quick Start

**Requirements:** Python 3.11+

```bash
# Install server dependencies
cd server
pip install -r requirements.txt
python main.py          # starts on port 3000

# In a second terminal — install and run the tool
cd tool
pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the test suite
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/hashes#sha256",
      "vulnerability_type": "FAST_HASH_ALGORITHM",
      "evidence": "SHA256 hashes in 0.0019 ms per operation. No work factor — computes in microseconds. GPUs can test billions of SHA-256 passwords per second. Should never be used for password storage. Dictionary attack recovered password \"password123\" in 0.41 ms after 2 attempt(s).",
      "severity": "HIGH"
    }
  ],
  "summary": "1 vulnerability(s) found. Unsafe algorithms: sha256. Safe algorithms (no findings): bcrypt, scrypt, argon2. Replace fast hashes with bcrypt (cost ≥12), scrypt, or argon2id."
}
```

Stderr (human-readable progress):

```
[*] Connecting to http://localhost:3000
[*] Benchmark results:
    sha256      0.002 ms  [UNSAFE]
    bcrypt    312.450 ms  [safe]
    scrypt     38.220 ms  [safe]
    argon2     28.110 ms  [safe]
[-] sha256: UNSAFE — attempting dictionary attack …
[!] CRACKED: 'password123' recovered in 0.41 ms (2 attempt(s))
[+] bcrypt: safe — Adaptive work factor (cost 12 ≈ 300ms). Designed for passwords…
[+] scrypt: safe — Memory-hard KDF (n=16384, ~128 MiB). High memory requirement…
[+] argon2: safe — Winner of the 2015 Password Hashing Competition. argon2id…

[*] Summary: 1 vulnerability(s) found. Unsafe algorithms: sha256. ...
```

## Key Takeaways

1. **Never use general-purpose cryptographic hashes (SHA-2, MD5) for passwords.** They are designed to be fast — which is exactly what attackers need.

2. **bcrypt** remains the safest default: its serial Feistel design prevents GPU parallelism, and its cost factor lets you increase work as hardware improves. Use cost ≥12 in 2025+.

3. **scrypt** adds a memory requirement (n=16384 → 128 MiB), defeating ASICs. Suitable for systems with available RAM.

4. **argon2id** is the modern recommendation (OWASP, NIST). It combines time-hardness, memory-hardness, and side-channel resistance in one parameter set.

5. **The cost factor must grow with hardware.** A hash that takes 300 ms today may be trivially fast in five years. Review your bcrypt cost factor annually.

6. **A cracked hash database is a credential stuffing kit.** Passwords are reused across sites. A fast hash on one service compromises accounts on every service that user touches.

## Further Reading

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 7914 — The scrypt Password-Based Key Derivation Function](https://www.rfc-editor.org/rfc/rfc7914)
- [Argon2 — Password Hashing Competition winner specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
