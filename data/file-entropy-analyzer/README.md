# File Entropy Analyzer

Detects packed, encrypted, or obfuscated files by measuring Shannon entropy — a key technique in malware triage and forensic analysis.

---

## What This Demonstrates

**Shannon entropy** measures how unpredictable (or "random") the bytes in a file are, reported as bits per byte on a scale of 0–8:

| Range | Typical content | Suspicious? |
|---|---|---|
| 0–3 | Repeated patterns, padding, sparse data | No |
| 3–6 | Natural language text, source code, JSON | No |
| 6–7.5 | Compiled binaries, compressed archives | Possibly |
| 7.5–8 | Encrypted ciphertext, packed malware, compressed blobs | Yes |

Malware authors routinely pack or encrypt their payloads to evade signature-based detection. A file that looks harmless from its extension but has near-8.0 entropy is a strong indicator worth investigating further.

---

## How It Works

```
demo server  ──→  /files listing   ──→  tool downloads each file
                  /files/:type            ↓
                  /safe/files/:type  calculates entropy (Shannon formula)
                                         ↓
                                    classifies: low / medium / high / very_high
                                         ↓
                                    emits structured JSON findings
```

- **Server** generates four files at startup: one repetitive (entropy ~0), one English text (~4 b/B), and two cryptographically random blobs (~8 b/B) simulating encrypted vault content.
- **Tool** discovers files via `/files`, fetches each binary, computes entropy byte-by-byte, and flags anything above 6.0 bits/byte as suspicious.
- **Tests** verify true positives (random data flagged), false positives suppressed (text not flagged), JSON output shape, and graceful error handling.

---

## Quick Start

```bash
# Install
cd server && npm install && cd ..

# Run the demo server
node server/index.js
# → Server running on port 3000

# Run the entropy scanner (in another terminal)
node tool/index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

---

## Example Output

```json
{
  "target": "http://localhost:3000",
  "timestamp": "2026-06-08T10:14:22.000Z",
  "findings": [
    {
      "endpoint": "/files/high",
      "vulnerability_type": "high_entropy_content",
      "evidence": "entropy 7.9981 bits/byte exceeds threshold 6.0 — file: random.bin",
      "severity": "HIGH",
      "entropy": 7.9981,
      "classification": "encrypted_or_packed",
      "size_bytes": 10240,
      "filename": "random.bin"
    },
    {
      "endpoint": "/files/encrypted",
      "vulnerability_type": "high_entropy_content",
      "evidence": "entropy 7.9976 bits/byte exceeds threshold 6.0 — file: vault.enc",
      "severity": "HIGH",
      "entropy": 7.9976,
      "classification": "encrypted_or_packed",
      "size_bytes": 10240,
      "filename": "vault.enc"
    }
  ],
  "summary": {
    "total_files_analyzed": 4,
    "high_entropy_count": 2,
    "suspicious_files": ["high", "encrypted"]
  }
}
```

---

## Key Takeaways

1. **High entropy is a signal, not proof.** Compressed archives and legitimate encrypted backups also score near 8.0. Entropy is a triage filter, not a verdict.
2. **Low-entropy malware exists.** Polymorphic engines and self-decoding stubs may carry low-entropy loaders; entropy alone is not sufficient for detection.
3. **Combine with other signals.** Pair entropy scores with file extension mismatches, unusual section names in PE headers, and behavioral analysis for stronger confidence.
4. **The constant-time loop matters.** Iterating over all 256 byte values (even empty buckets) keeps the algorithm O(n) and avoids timing side-channels.

---

## Further Reading

- [OWASP Testing Guide — Malicious File Upload](https://owasp.org/www-community/attacks/Malicious_File_Upload)
- [Shannon Entropy — Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Node.js crypto module](https://nodejs.org/api/crypto.html)
