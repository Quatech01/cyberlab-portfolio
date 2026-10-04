# Password Strength Analyzer

A Python security tool that evaluates password policy enforcement by probing registration endpoints, calculating Shannon entropy, detecting common patterns, and comparing what a vulnerable server accepts versus what a hardened one rejects.

## What This Demonstrates

Weak password policies are one of the most persistent causes of account compromise. This project covers three complementary analysis techniques:

1. **Entropy-based scoring** — how many bits of randomness a password actually contains, derived from charset size and length
2. **Pattern detection** — keyboard walks (`qwerty`), dictionary words, leetspeak substitutions that still resolve to common words
3. **Policy enforcement testing** — black-box probing of registration endpoints to determine whether a server genuinely rejects weak credentials or only pretends to

The demo server exposes two registration paths side by side: one with no policy (accepts `123456`), one that enforces a minimum 12-character, multi-class, entropy-gated policy using bcrypt. The scanner detects the difference automatically.

## How It Works

```
server/main.py  ← FastAPI server
│
├── GET  /health                  returns {"status":"ok"}
├── GET  /api/policy/unsafe       returns policy config (weak: no enforcement)
├── GET  /api/policy/safe         returns policy config (strong: all checks enabled)
├── POST /api/register/unsafe     accepts ANY non-empty password (MD5 hash — intentionally weak)
├── POST /api/register/safe       enforces: 12+ chars, upper, lower, digit, special, entropy ≥ 50 bits, bcrypt
└── POST /api/analyze             returns server-side entropy score and strength label

tool/main.py    ← CLI scanner
│
├── Reads /api/policy/unsafe → flags weak configuration in JSON findings
├── Probes /api/register/unsafe with 6 weak test passwords → HIGH findings per accepted password
├── Probes /api/register/safe with same passwords → CRITICAL if any are accepted (false negative)
├── Runs local entropy + pattern analysis on each test password
└── Outputs structured JSON: { target, findings[], summary }

tests/test.py   ← pytest suite (30 tests)
├── Group 1: health and policy endpoints reachable
├── Group 2: true positives — unsafe endpoint accepts weak passwords, tool detects them
├── Group 3: false positives — safe endpoint rejects weak passwords, tool doesn't mis-flag it
├── Group 4: output format — all required JSON fields present and typed correctly
└── Group 5: edge cases — unreachable server, empty inputs, duplicate registration
```

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt && cd ..

# Install tool dependencies
cd tool && pip install -r requirements.txt && cd ..

# Run the demo server (port 3000)
python server/main.py

# Run the scanner against it (in a separate terminal)
python tool/main.py --target http://localhost:3000

# Run the full test suite
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
      "endpoint": "/api/policy/unsafe",
      "vulnerability_type": "policy_allows_common_passwords",
      "evidence": "Policy config exposes blocks_common_passwords=false, min_length=1, min_entropy_bits=0",
      "severity": "HIGH"
    },
    {
      "endpoint": "/api/register/unsafe",
      "vulnerability_type": "weak_password_policy",
      "evidence": "Accepted password '123456' — entropy: 19.93 bits, strength: weak, issues: common_password, very_low_entropy, no_uppercase, no_lowercase, no_special_char",
      "severity": "HIGH"
    },
    {
      "endpoint": "/api/register/unsafe",
      "vulnerability_type": "weak_password_policy",
      "evidence": "Accepted password 'password' — entropy: 37.6 bits, strength: weak, issues: common_password, low_entropy, no_uppercase, no_digit, no_special_char",
      "severity": "HIGH"
    }
  ],
  "summary": "Scanned http://localhost:3000: 8 high/critical policy issue(s) detected. /api/register/unsafe accepted 6/6 weak test passwords. /api/register/safe correctly rejected all weak passwords."
}
```

## Key Takeaways

- **Entropy formula**: `bits = length × log₂(charset_size)`. A 6-digit numeric PIN has only `6 × log₂(10) = 19.9 bits` — crackable in milliseconds offline.
- **Common password lists matter**: entropy alone does not prevent dictionary attacks. `P@ssw0rd` scores 52 bits but is in every cracking list.
- **Leetspeak is not a defence**: substituting `a→@` or `o→0` is trivially reversed before a dictionary check.
- **MD5 for passwords is never acceptable**: even a salted MD5 can be cracked at ~10 billion hashes/second with a GPU. bcrypt at cost 12 reduces that to thousands.
- **Test your policy**: the only way to confirm your registration endpoint rejects weak passwords is to try them — configuration and code often diverge.

## Further Reading

- [OWASP Authentication Cheat Sheet — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B — Digital Identity Guidelines (passwords)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Testing Guide — Testing for Weak Password Policy](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy)
