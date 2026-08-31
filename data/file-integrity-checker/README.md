# File Integrity Checker

A tool that detects unauthorized file modifications by comparing SHA-256 hashes against a trusted baseline — the same principle used by production FIM systems like OSSEC, Tripwire, and AIDE.

## What This Demonstrates

File Integrity Monitoring (FIM) is a core defensive control in security operations. When an attacker gains access to a system, one of their first actions is often to modify system files — replacing authentication handlers with backdoored versions, injecting reverse-shell code into database connectors, or altering configuration to escalate privileges.

FIM tools prevent this by:
1. Computing cryptographic hashes of critical files at a known-good baseline
2. Periodically re-hashing those files and comparing against the baseline
3. Alerting on any mismatch, since even a single changed byte produces a completely different SHA-256 hash

This project demonstrates two tampered files:
- **`auth.py`** — the password verification function has been replaced with `return True`, granting every login attempt regardless of credentials
- **`db_connector.py`** — a reverse-shell subprocess call has been injected alongside the legitimate database code, establishing a C2 channel on connection

Both are HIGH severity because they represent post-exploitation persistence in critical application components.

## How It Works

```
┌─────────────────────────────────────────┐
│  Demo Server (FastAPI, port 3000)       │
│                                         │
│  GET /files     → integrity manifest    │
│                   (filenames + SHA-256  │
│                    baseline hashes)     │
│                                         │
│  GET /file/{name} → current content     │
│    config.ini    → CLEAN (unchanged)    │
│    app.js        → CLEAN (unchanged)    │
│    styles.css    → CLEAN (unchanged)    │
│    readme.txt    → CLEAN (unchanged)    │
│    auth.py       → TAMPERED (backdoor)  │
│    db_connector  → TAMPERED (revshell)  │
└─────────────────────────────────────────┘
           ↓ HTTP
┌─────────────────────────────────────────┐
│  Tool (tool/main.py)                    │
│  1. Fetch manifest from /files          │
│  2. For each file: fetch /file/{name}   │
│  3. Compute SHA-256(current_content)    │
│  4. Compare with baseline_hash          │
│  5. Report mismatches as findings       │
└─────────────────────────────────────────┘
```

The tests verify that:
- The server starts and the manifest endpoint is accurate
- The tool correctly flags both tampered files as `INTEGRITY_VIOLATION / HIGH`
- The four clean files produce zero findings (no false positives)
- Output is valid JSON with all required fields
- An unreachable server produces empty findings without crashing

## Quick Start

**Requirements:** Python 3.11+

```bash
# Install server dependencies
cd server && pip install -r requirements.txt && cd ..

# Install tool dependencies
cd tool && pip install -r requirements.txt && cd ..

# Run the demo server
cd server && python main.py
# Server listens on http://127.0.0.1:3000

# In a second terminal: run the tool
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
      "endpoint": "/file/auth.py",
      "vulnerability_type": "INTEGRITY_VIOLATION",
      "evidence": "File 'auth.py' has been modified. Baseline SHA-256: a3f9c2d1e4b5f678..., Current SHA-256: 9d4e2a71c38fb052...",
      "severity": "HIGH"
    },
    {
      "endpoint": "/file/db_connector.py",
      "vulnerability_type": "INTEGRITY_VIOLATION",
      "evidence": "File 'db_connector.py' has been modified. Baseline SHA-256: 7b1c3a9e5d2f6840..., Current SHA-256: 2e8f1c4a7d903b56...",
      "severity": "HIGH"
    }
  ],
  "summary": "2 integrity violation(s) detected in 6 files checked (4 file(s) verified clean)."
}
```

When all files are clean:

```json
{
  "target": "http://localhost:3000",
  "findings": [],
  "summary": "All 6 files match their baseline hashes. No integrity violations detected."
}
```

## Key Takeaways

- **SHA-256 is collision-resistant** — an attacker cannot produce a modified file that has the same hash as the original without computational infeasibility
- **The baseline must be protected** — if an attacker can modify both the file and the stored hash, FIM is defeated. In production, baselines are stored on read-only media or signed with a private key
- **Critical paths deserve higher check frequency** — auth handlers and database connectors change rarely in production; any change should be treated as an immediate alert
- **FIM catches post-exploitation persistence** — it is most valuable after an initial compromise is detected, for tracing what the attacker modified
- **Even a one-byte change is detectable** — the avalanche property of SHA-256 ensures tiny modifications produce a completely different hash

## Further Reading

- [NIST SP 800-123 — Guide to General Server Security (Section 4.2: File Integrity Monitoring)](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [OSSEC File Integrity Monitoring documentation](https://www.ossec.net/docs/manual/syscheck/index.html)
- [OWASP — Protect Data Everywhere (integrity controls)](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)
