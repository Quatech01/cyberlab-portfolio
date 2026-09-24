# Robots.txt and Sitemap Analyzer

A reconnaissance tool that parses `robots.txt` and `sitemap.xml` to surface sensitive paths that organisations inadvertently publish to search engines and crawlers.

## What This Demonstrates

`robots.txt` was designed to tell well-behaved crawlers which paths to avoid. In practice, the `Disallow:` entries often read like a directory listing of the most sensitive parts of a web application — `/admin`, `/.git`, `/backup`, `/api/internal`. The file is always public and unauthenticated.

`sitemap.xml`, intended to help search engines index public content, sometimes ends up containing development URLs, staging environments, and internal tooling that was never meant to be public.

This project demonstrates:
- How `robots.txt` disclosure gives attackers a prioritised list of interesting attack surfaces
- How `sitemap.xml` can surface development and staging paths through search engine indexing
- Severity classification of disclosed paths (HIGH for version control and admin panels, MEDIUM for config/backup/staging, LOW for development endpoints)
- The difference between informational disclosure (the path exists) and actual exploitation (accessing the path)

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  Demo Server (FastAPI)                                          │
│                                                                 │
│  /robots.txt        → Discloses: /admin, /.git, /backup,       │
│                       /config, /api/internal, /staging,         │
│                       /phpmyadmin. References /sitemap.xml.     │
│                                                                 │
│  /sitemap.xml       → Contains: /dev/notes, /test/data,         │
│                       /staging/preview alongside public pages.  │
│                                                                 │
│  /safe-robots.txt   → Disallow: (empty). References             │
│                       /safe-sitemap.xml.                        │
│                                                                 │
│  /safe-sitemap.xml  → Public pages only: /, /about, /products, │
│                       /contact.                                 │
└──────────────┬──────────────────────────────────────────────────┘
               │ HTTP
┌──────────────▼──────────────────────────────────────────────────┐
│  Tool (tool/main.py)                                            │
│                                                                 │
│  1. Fetch {target}/robots.txt (or --robots-path override)       │
│  2. Parse Disallow: entries, classify against pattern library   │
│  3. Follow Sitemap: directive, fetch referenced XML             │
│  4. Extract <loc> URLs, classify each path                      │
│  5. Output structured JSON findings to stdout                   │
└─────────────────────────────────────────────────────────────────┘
```

The tests verify:
- All 7 sensitive paths in the vulnerable `robots.txt` are detected
- All 3 sensitive paths in the revealing sitemap are detected
- The safe `robots.txt` and safe sitemap produce zero findings
- Benign paths (`/images`, `/css`) are not flagged
- Unreachable servers are handled gracefully

## Quick Start

```bash
# Install dependencies
pip install fastapi uvicorn httpx

# Start the demo server
python server/main.py

# Run the scanner (in a second terminal)
python tool/main.py --target http://localhost:3000

# Scan the safe configuration (no findings expected)
python tool/main.py --target http://localhost:3000 --robots-path /safe-robots.txt

# Run the tests
pip install pytest
cd tests && python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "http://localhost:3000/robots.txt",
      "vulnerability_type": "SENSITIVE_PATH_DISCLOSED",
      "evidence": "Disallow: /.git (pattern: \\.git)",
      "severity": "HIGH"
    },
    {
      "endpoint": "http://localhost:3000/robots.txt",
      "vulnerability_type": "SENSITIVE_PATH_DISCLOSED",
      "evidence": "Disallow: /phpmyadmin (pattern: phpmyadmin)",
      "severity": "HIGH"
    },
    {
      "endpoint": "http://localhost:3000/robots.txt",
      "vulnerability_type": "SENSITIVE_PATH_DISCLOSED",
      "evidence": "Disallow: /admin (pattern: /admin(?:/|$))",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "http://localhost:3000/robots.txt",
      "vulnerability_type": "SENSITIVE_PATH_DISCLOSED",
      "evidence": "Disallow: /backup (pattern: /backup)",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "http://localhost:3000/sitemap.xml",
      "vulnerability_type": "SITEMAP_PATH_DISCLOSED",
      "evidence": "http://localhost:3000/dev/notes (path: /dev/notes, pattern: /dev(?:/|$))",
      "severity": "LOW"
    },
    {
      "endpoint": "http://localhost:3000/sitemap.xml",
      "vulnerability_type": "SITEMAP_PATH_DISCLOSED",
      "evidence": "http://localhost:3000/staging/preview (path: /staging/preview, pattern: /staging)",
      "severity": "MEDIUM"
    }
  ],
  "summary": "7 sensitive path(s) in robots.txt, 3 sensitive URL(s) in sitemap(s)"
}
```

## Key Takeaways

- **robots.txt is not a security control** — it is a polite request, not enforcement. Any malicious actor reads it before anything else.
- **Disallow entries map your attack surface** — every path you exclude tells an attacker exactly what is worth probing. Sensitive directories should not be listed at all; they should be protected by authentication at the server level.
- **Sitemaps are indexed by Google** — paths you include in `sitemap.xml` may appear in search results even if they return 404 today. Development and staging URLs are best kept off the sitemap entirely.
- **Severity tiers matter** — a `.git` directory exposure is critical (full source code and secrets); a `/dev` path is informational. Prioritise your remediation accordingly.
- **The fix is defence-in-depth** — remove sensitive paths from `robots.txt`, restrict them with authentication, and use a staging domain that is never indexed.

## Further Reading

- [OWASP Testing Guide: Review Webserver Metafiles for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [robots.txt specification — robotstxt.org](https://www.robotstxt.org/robotstxt.html)
- [Sitemaps protocol — sitemaps.org](https://www.sitemaps.org/protocol.html)
