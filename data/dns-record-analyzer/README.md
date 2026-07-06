# DNS Record Analyzer

Audits DNS records for email authentication misconfigurations — the leading vector for domain spoofing and phishing.

## What This Demonstrates

Email spoofing is trivially easy when a domain lacks proper DNS authentication records. Two standards close this gap:

- **SPF (Sender Policy Framework)** — a TXT record listing the mail servers authorised to send on behalf of a domain. An absent SPF record lets anyone send mail as you. A misconfigured `+all` qualifier makes the record pointless by permitting every server on the internet.
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)** — instructs receiving mail servers what to do when SPF or DKIM checks fail. Without DMARC, a receiving server has no policy to enforce even if SPF fails. A DMARC record with `p=none` only monitors — it never quarantines or rejects spoofed mail.

This project scans a mock DNS API, identifies these misconfigurations, and reports findings at HIGH or MEDIUM severity.

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│                     Express Demo Server                   │
│                                                          │
│  GET /domains          → list of four test domains        │
│  GET /dns?domain=&type= → mock DNS records per domain     │
│                                                          │
│  secure.example.com    → strict SPF (-all) + DMARC reject │
│  vulnerable.example.com→ permissive SPF (+all), no DMARC  │
│  noauth.example.com    → no SPF, no DMARC                 │
│  partial.example.com   → valid SPF, DMARC p=none          │
└──────────────────────────────────────────────────────────┘
         ↑ HTTP GET
┌──────────────────────────────────────────────────────────┐
│                    DNS Analyzer Tool                      │
│                                                          │
│  1. Fetches domain list from /domains                    │
│  2. For each domain, fetches all record types            │
│  3. Parses TXT records for SPF and DMARC                 │
│  4. Flags: missing SPF, +all SPF, missing DMARC,        │
│            DMARC p=none                                  │
│  5. Outputs structured JSON findings                     │
└──────────────────────────────────────────────────────────┘
```

The test suite proves the scanner finds every real issue (true positives), leaves the correctly configured domain clean (false positive check), and degrades gracefully when the server is unreachable.

## Quick Start

```bash
# Install server dependencies
cd server && npm install && cd ..

# Run the demo server
node server/index.js

# In a second terminal — run the analyzer tool
node tool/index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/dns?domain=vulnerable.example.com&type=TXT",
      "vulnerability_type": "permissive_spf_record",
      "evidence": "SPF record for vulnerable.example.com uses +all, permitting any server to send mail: \"v=spf1 +all\"",
      "severity": "HIGH"
    },
    {
      "endpoint": "/dns?domain=vulnerable.example.com&type=TXT",
      "vulnerability_type": "missing_dmarc_record",
      "evidence": "No DMARC TXT record found for vulnerable.example.com — SPF/DKIM results are not enforced",
      "severity": "HIGH"
    },
    {
      "endpoint": "/dns?domain=noauth.example.com&type=TXT",
      "vulnerability_type": "missing_spf_record",
      "evidence": "No SPF TXT record found for noauth.example.com — any mail server can send on its behalf",
      "severity": "HIGH"
    },
    {
      "endpoint": "/dns?domain=noauth.example.com&type=TXT",
      "vulnerability_type": "missing_dmarc_record",
      "evidence": "No DMARC TXT record found for noauth.example.com — SPF/DKIM results are not enforced",
      "severity": "HIGH"
    },
    {
      "endpoint": "/dns?domain=partial.example.com&type=TXT",
      "vulnerability_type": "dmarc_policy_none",
      "evidence": "DMARC for partial.example.com uses p=none (monitoring only, no enforcement): \"v=DMARC1; p=none; rua=mailto:reports@partial.example.com\"",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Analyzed 4 domain(s): 5 issue(s) found — 4 HIGH, 1 MEDIUM"
}
```

## Key Takeaways

- **Missing SPF is exploitable immediately.** Any attacker can forge your domain in the `From:` header and many mail clients will show it as legitimate.
- **SPF `+all` is equivalent to no SPF.** The qualifier says "all servers are authorised" — the record offers zero protection.
- **DMARC `p=none` is a trap.** It collects reports but never takes action. Attackers are unaffected; only the domain owner's inbox fills with XML reports.
- **The correct stack:** SPF with `-all` (hard fail) + DKIM signing + DMARC with `p=reject`.
- **DNS authentication is free and well-supported.** There is no technical barrier to fixing these issues — the barrier is operational awareness.

## Further Reading

- [RFC 7208 — Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 7489 — DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [OWASP Email Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing)
