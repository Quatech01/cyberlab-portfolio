# HTTP Technology Fingerprinter

A scanner that identifies web frameworks and platforms from passive HTTP response analysis — no active exploitation, no guessing. It reads headers, cookies, and HTML patterns that applications expose by default.

## What This Demonstrates

Modern web applications inadvertently disclose their technology stack through response characteristics that frameworks add automatically:

- **Server and X-Powered-By headers** — Apache, gunicorn, and Express announce themselves in every response unless explicitly suppressed.
- **Framework-specific cookie names** — `csrftoken` (Django), `wordpress_logged_in_*` (WordPress), `_<app>_session` (Rails) are hardcoded into the framework.
- **HTML meta tags** — WordPress's `<meta name="generator">` tag was opt-out for years.
- **Asset path conventions** — `/wp-content/`, `/_next/static/`, `/static/js/*.chunk.js` are deterministic outputs of each build toolchain.
- **Diagnostic headers** — Rails adds `X-Runtime` (response time in seconds) and `X-Request-Id` (UUID) to every response via default middleware.

This information helps attackers target known CVEs for specific versions. The mitigation is suppression — removing or replacing these headers and asset paths in production.

## How It Works

```
server/main.py          FastAPI demo server
    /site/wordpress     WordPress fingerprint (PHP header, wp-content paths, session cookie, meta generator)
    /site/react         React SPA fingerprint (Express header, data-reactroot, chunk.js paths)
    /site/django        Django fingerprint (gunicorn, X-Frame-Options, csrftoken cookie, csrfmiddlewaretoken field)
    /site/rails         Rails fingerprint (X-Runtime, X-Request-Id, _app_session cookie, authenticity_token)
    /site/nextjs        Next.js fingerprint (X-Powered-By: Next.js, /_next/static/, __NEXT_DATA__ script)
    /site/clean         Baseline — no framework-specific indicators (safe endpoint)
    /targets            Lists all scan targets

tool/main.py            Fingerprinting scanner
    Fetches /targets to discover endpoints
    For each endpoint, analyzes headers, cookies, and HTML body against rule set
    Each rule requires ≥2 matching indicators to avoid false positives
    Emits structured JSON findings

tests/test.py           Test suite (35 tests)
    Group 1: Server health and /targets availability
    Group 2: True positive detection for all 5 tech stacks
    Group 3: False positive suppression — clean endpoint produces zero findings
    Group 4: Output format validation (JSON structure, required fields)
    Group 5: Edge cases — unreachable server, network errors
```

## Quick Start

```bash
cd repos/http-technology-fingerprinter

# Install dependencies
cd server && pip install -r requirements.txt
cd ../tool && pip install -r requirements.txt

# Run the demo server
cd server && python main.py
# Server now listening on http://127.0.0.1:3000

# Run the fingerprinter (in a separate terminal)
cd tool && python main.py --target http://localhost:3000

# Run tests
cd tests && pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/site/wordpress",
      "vulnerability_type": "technology_disclosure",
      "evidence": "X-Powered-By header reveals PHP runtime: PHP/8.1.29; Server header reveals Apache httpd: Apache/2.4.57 (Ubuntu); Cookie 'wordpress_logged_in' is WordPress's default authenticated session cookie; Meta generator tag explicitly identifies WordPress CMS version; Path '/wp-content/' is exclusive to WordPress plugin and theme assets",
      "severity": "MEDIUM",
      "technology": "WordPress"
    },
    {
      "endpoint": "/site/react",
      "vulnerability_type": "technology_disclosure",
      "evidence": "X-Powered-By: Express is the default Express.js server header; Attribute 'data-reactroot' is injected by React's server-side renderer; Script path '/static/js/*.chunk.js' matches Create React App's code-split output",
      "severity": "LOW",
      "technology": "React"
    },
    {
      "endpoint": "/site/django",
      "vulnerability_type": "technology_disclosure",
      "evidence": "Server header reveals gunicorn WSGI server, commonly deployed with Django: gunicorn/20.1.0; X-Frame-Options: SAMEORIGIN is set by Django's XFrameOptionsMiddleware by default; Cookie named 'csrftoken' is Django's default CSRF cookie name; Hidden field 'csrfmiddlewaretoken' is Django's default CSRF form field name",
      "severity": "MEDIUM",
      "technology": "Django"
    },
    {
      "endpoint": "/site/rails",
      "vulnerability_type": "technology_disclosure",
      "evidence": "X-Runtime header (response time in seconds) is added by Rails' Rack::Runtime middleware: 0.032s; X-Request-Id UUID header is added by Rails' ActionDispatch::RequestId middleware; Cookie name matching '_<app>_session' follows Rails' default session cookie naming convention; Hidden field 'authenticity_token' is Rails' CSRF token field name",
      "severity": "MEDIUM",
      "technology": "Ruby on Rails"
    },
    {
      "endpoint": "/site/nextjs",
      "vulnerability_type": "technology_disclosure",
      "evidence": "X-Powered-By header explicitly identifies Next.js framework; Path '/_next/static/' is Next.js's reserved static asset namespace; Script tag id='__NEXT_DATA__' is Next.js's server-side props injection mechanism",
      "severity": "LOW",
      "technology": "Next.js"
    }
  ],
  "summary": "Detected technology fingerprints on 5 endpoint(s): Django, Next.js, React, Ruby on Rails, WordPress. 1 endpoint(s) revealed no identifying information."
}
```

## Key Takeaways

1. **Default headers are the loudest signal.** `X-Powered-By` and `Server` headers exist solely to help developers debug — remove them in production via `ServerTokens Prod` (Apache), `server_tokens off` (nginx), or `app.disable('x-powered-by')` (Express).

2. **Cookie names are framework fingerprints.** `csrftoken`, `wordpress_logged_in_*`, and `_<app>_session` are set by the framework with no configuration. Rename them in production settings: `SESSION_COOKIE_NAME` (Django), `config.session_store` (Rails), WordPress `COOKIEHASH` filter.

3. **Asset paths reveal build tools.** `/wp-content/` and `/_next/static/` are hardcoded by WordPress and Next.js respectively. Reverse-proxy rewrites can obscure them but add complexity.

4. **Diagnostic middleware adds observable headers.** Rails' `Rack::Runtime` and `ActionDispatch::RequestId` middleware are enabled by default. Remove them in `config/application.rb` for production: `config.middleware.delete Rack::Runtime`.

5. **Two-indicator minimum prevents false positives.** Any single header or cookie can appear coincidentally. The scanner requires ≥2 independent signals per technology before reporting a finding, reducing noise.

## Further Reading

- [OWASP Testing for Application Discovery via HTTP Headers (WSTG-INFO-02)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [OWASP Testing for Application Platform Fingerprinting (WSTG-INFO-08)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
- [MDN Web Docs — X-Powered-By header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Powered-By)
