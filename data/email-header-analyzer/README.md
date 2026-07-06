# Email Header Analyzer

A security tool that parses raw email headers to detect authentication failures, spoofed senders, and weak DMARC enforcement policies.

## What This Demonstrates

Email authentication relies on three cooperating DNS-based protocols:

- **SPF** (Sender Policy Framework) — the sending domain publishes a list of authorised mail servers in its DNS. Receiving servers check whether the email's envelope sender matches that list.
- **DKIM** (DomainKeys Identified Mail) — the sending server cryptographically signs outbound mail. Receivers verify the signature against a public key in DNS.
- **DMARC** (Domain-based Message Authentication, Reporting & Conformance) — the domain owner declares a policy (`p=none`, `p=quarantine`, or `p=reject`) that tells receivers what to do with mail that fails SPF/DKIM alignment.

When these controls are absent or misconfigured, attackers can forge the `From:` address to impersonate trusted brands. This is the basis of the majority of phishing campaigns. This project shows how to programmatically detect each failure mode from the `Authentication-Results` header that receiving mail servers stamp onto every inbound message.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  FastAPI Demo Server (localhost:3000)                    │
│                                                          │
│  GET /samples          → list of 4 email header samples │
│  GET /samples/{id}     → raw email header string        │
│                                                          │
│  Samples:                                               │
│    clean           → SPF/DKIM/DMARC pass, p=reject      │
│    spoofed_sender  → SPF fail, DMARC fail, From mismatch│
│    missing_auth    → no Authentication-Results at all   │
│    dmarc_monitoring→ DMARC pass but p=none              │
└─────────────────────────────────────────────────────────┘
          ↕  HTTP (localhost only)
┌─────────────────────────────────────────────────────────┐
│  Analysis Tool (tool/main.py)                            │
│                                                          │
│  1. Fetch sample list from /samples                      │
│  2. For each sample: fetch raw headers via HTTP          │
│  3. Parse with Python email module + regex               │
│  4. Detect: SPF failure, email spoofing, DMARC failure,  │
│             DMARC p=none, missing auth headers           │
│  5. Emit structured JSON to stdout                       │
└─────────────────────────────────────────────────────────┘
```

The 20-test suite verifies:
- The server starts cleanly and serves all four samples
- True positives: the tool flags every deliberately misconfigured sample
- False positives: the `clean` sample produces zero findings
- Output format: JSON contains `target`, `findings`, `summary`; each finding has `endpoint`, `vulnerability_type`, `evidence`, `severity`
- Edge cases: unreachable servers return empty findings without crashing; nonexistent samples return 404

## Quick Start

```bash
# Install server dependencies
cd server
pip install -r requirements.txt

# Run the demo server
python main.py
# Server listening on http://127.0.0.1:3000

# In another terminal — run the analysis tool
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
      "endpoint": "/samples/spoofed_sender",
      "vulnerability_type": "spf_failure",
      "evidence": "SPF result: fail. Envelope sender <attacker@evil.example> is not authorised to send on behalf of the From domain (trusted-bank.example).",
      "severity": "HIGH"
    },
    {
      "endpoint": "/samples/spoofed_sender",
      "vulnerability_type": "email_spoofing",
      "evidence": "From domain (trusted-bank.example) does not match envelope sender (evil.example) and DMARC did not pass.",
      "severity": "HIGH"
    },
    {
      "endpoint": "/samples/spoofed_sender",
      "vulnerability_type": "dmarc_failure",
      "evidence": "DMARC validation failed for header.from=trusted-bank.example. Mail bypasses the domain owner's enforcement policy.",
      "severity": "HIGH"
    },
    {
      "endpoint": "/samples/missing_auth",
      "vulnerability_type": "missing_email_authentication",
      "evidence": "No Authentication-Results header present. SPF, DKIM, and DMARC cannot be verified for mail claiming to be from <Billing Department <billing@unknown-domain.example>>.",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/samples/dmarc_monitoring",
      "vulnerability_type": "dmarc_policy_none",
      "evidence": "DMARC policy is p=none (monitoring only). Spoofed emails from this domain are reported but never quarantined or rejected by receiving servers.",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Analysed 4 email header samples; 3/4 had findings. 5 total finding(s) detected."
}
```

## Key Takeaways

1. **SPF alone is not enough.** An attacker can easily send mail from a domain they control (passing SPF for their domain) while forging the `From:` display address to impersonate someone else. DMARC alignment bridges that gap.

2. **DMARC p=none is not protection.** Domains that have deployed DMARC but left the policy at `p=none` generate aggregate reports but still deliver every spoofed email. A domain is not protected until the policy reaches `p=reject`.

3. **Authentication-Results is the single source of truth.** Receiving mail servers stamp this header with the outcome of all three checks. Parsing it programmatically gives a reliable, tamper-resistant view of what the sending infrastructure looked like.

4. **Phishing detection at the header level is fast.** The entire analysis in this tool uses only the stdlib `email` module and regex — no network calls beyond fetching the headers themselves. Header inspection is computationally cheap and can run at ingest time.

## Further Reading

- [OWASP: Email Security](https://owasp.org/www-community/controls/Email_Security)
- [RFC 7208 — Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://datatracker.ietf.org/doc/html/rfc7489)
