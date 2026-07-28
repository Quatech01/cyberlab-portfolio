# Subdomain Enumerator

A wordlist-based subdomain discovery tool that maps an organisation's external attack surface by probing common subdomain labels against a mock DNS resolver. Demonstrates how forgotten development environments and exposed management interfaces become entry points for attackers.

## What This Demonstrates

**Subdomain enumeration** is one of the first steps in any reconnaissance phase. Attackers iterate through a wordlist of common labels (`admin`, `dev`, `staging`, `db`, `vpn`, …), probe each one for a live DNS record, and note which ones resolve. Sensitive subdomains often:

- Run older software without the same patching cadence as production
- Lack WAF protection or rate limiting because "it's only internal"
- Expose admin panels or database management interfaces
- Leak environment variables and debug endpoints

This project shows the complete workflow: mock resolver, wordlist probing, resolution detection, and severity classification based on subdomain name sensitivity.

## How It Works

- **`server/`** — FastAPI app acting as a mock DNS-over-HTTP resolver. `GET /resolve?name=<fqdn>` returns `{"address": "127.0.0.X", "ttl": 300}` for the 10 configured subdomains (`www`, `mail`, `api`, `admin`, `dev`, `staging`, `db`, `internal`, `vpn`, `test`) and `{"error": "NXDOMAIN"}` with status 404 for everything else.
- **`tool/`** — Python scanner that iterates a 60-label wordlist, queries the resolver for each candidate FQDN, and classifies discovered subdomains: HIGH for management and infrastructure labels, MEDIUM for API gateways, LOW for generic services.
- **`tests/`** — Pytest suite with 30 tests across five groups: server health, true positive detection, false positive suppression, output format validation, and edge-case handling for unreachable servers.

## Quick Start

```bash
# Install dependencies
cd server && pip install -r requirements.txt
cd ../tool && pip install -r requirements.txt

# Start the mock DNS resolver
cd server && python main.py
# Server listening on http://127.0.0.1:3000

# Run the enumerator (in a separate terminal)
cd tool && python main.py --target http://localhost:3000 --domain example.com

# Run all tests
cd tests && pip install -r requirements.txt && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "domain": "example.com",
  "words_probed": 63,
  "findings": [
    {
      "endpoint": "www.example.com",
      "vulnerability_type": "subdomain_discovered",
      "evidence": "Resolved to 127.0.0.1 (TTL 300s)",
      "severity": "LOW",
      "address": "127.0.0.1"
    },
    {
      "endpoint": "api.example.com",
      "vulnerability_type": "subdomain_discovered",
      "evidence": "Resolved to 127.0.0.3 (TTL 300s)",
      "severity": "MEDIUM",
      "address": "127.0.0.3"
    },
    {
      "endpoint": "admin.example.com",
      "vulnerability_type": "subdomain_discovered",
      "evidence": "Resolved to 127.0.0.4 (TTL 300s)",
      "severity": "HIGH",
      "address": "127.0.0.4"
    },
    {
      "endpoint": "dev.example.com",
      "vulnerability_type": "subdomain_discovered",
      "evidence": "Resolved to 127.0.0.5 (TTL 300s)",
      "severity": "HIGH",
      "address": "127.0.0.5"
    }
  ],
  "summary": "Discovered 10 subdomain(s) for example.com: 7 HIGH, 1 MEDIUM, 2 LOW severity."
}
```

## Key Takeaways

1. **Sensitive subdomains are discovered the same way legitimate services are.** There is no reliable way to "hide" a publicly-resolvable subdomain from an attacker with a wordlist.
2. **Dev and staging environments share your production domain.** If `staging.example.com` resolves publicly, it can be probed, attacked, and used as a pivot — even if no link to it appears on the main site.
3. **Severity by name is a first-pass heuristic, not ground truth.** A subdomain called `old` might be harmless; one called `api2` might hold the most sensitive data. Use enumeration results as a starting point, then probe each discovered host individually.
4. **Mitigations.** Use split-horizon DNS so internal subdomains only resolve on the internal network. Regularly audit your external DNS zone for forgotten entries. Apply the same security controls to dev/staging as production.

## Further Reading

- [OWASP Testing Guide — Enumerate Applications on Webserver (OTG-INFO-004)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver)
- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [OWASP Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
