# CSP Generator

A Content Security Policy analysis and generation tool that scans web pages for resource patterns and policy gaps, then produces a tailored CSP header recommendation for each page.

## What This Demonstrates

Content Security Policy (CSP) is a browser security mechanism that mitigates cross-site scripting (XSS) by declaring precisely which dynamic resources a page is permitted to load. Without a CSP, the browser will execute any script the page contains — including injected ones.

This project shows how to:

- Parse HTML to catalogue every resource origin (scripts, stylesheets, images, frames)
- Detect unsafe patterns that force permissive CSP directives: inline `<script>` blocks, inline event handlers like `onclick`, and `eval()` calls
- Generate a minimal, page-specific CSP header based on what the page actually uses
- Distinguish pages that already have a policy (no false positive) from pages that are unprotected

## How It Works

```
demo server  ──▶  serves 4 HTML pages with different resource patterns
     │
   tool  ──▶  fetches /pages, analyzes each page's HTML
     │
   JSON  ──▶  findings per page + recommended CSP headers
```

**Demo server** (`server/main.py`): A FastAPI server with four test pages:

| Page | What it contains |
|------|-----------------|
| `/page/unsafe-inline` | Inline `<script>` block + `onclick` event handler — no CSP |
| `/page/cdn-resources` | Scripts and styles from external CDN origins — no CSP |
| `/page/strict-csp` | Same-origin resources only, with a strict CSP header already set |
| `/page/mixed` | Inline scripts, `eval()`, external scripts, and an `<iframe>` — no CSP |

**Scanner** (`tool/main.py`): Fetches the page list from `/pages`, visits each page, and for every page:
1. Extracts all resource origins using Python's `html.parser`
2. Flags missing CSP, inline scripts, event handlers, `eval()` usage, and external origins
3. Generates a tailored CSP directive string if the page lacks one

**Tests** (`tests/test.py`): 27 pytest tests covering server health, true-positive detection, false-positive prevention, output format, and edge cases.

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt

# Run the demo server
python server/main.py

# In a second terminal — run the scanner
cd tool
python main.py --target http://localhost:3000

# Run the tests
cd tests && pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "http://localhost:3000/page/unsafe-inline",
      "vulnerability_type": "missing_csp",
      "evidence": "No Content-Security-Policy header present on this page",
      "severity": "high",
      "recommended_csp": "script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; frame-src 'none'; default-src 'self'"
    },
    {
      "endpoint": "http://localhost:3000/page/unsafe-inline",
      "vulnerability_type": "inline_script_detected",
      "evidence": "Inline <script> block found — requires 'unsafe-inline' in script-src",
      "severity": "medium",
      "recommended_csp": null
    },
    {
      "endpoint": "http://localhost:3000/page/mixed",
      "vulnerability_type": "eval_usage_detected",
      "evidence": "eval() call found in inline script — requires 'unsafe-eval' in script-src",
      "severity": "high",
      "recommended_csp": null
    }
  ],
  "summary": "Analyzed 4 page(s). Found 11 issue(s): 5 high, 4 medium, 2 low."
}
```

## Key Takeaways

- **Absence of CSP is a high-severity finding** — without a policy, browsers will execute any injected script
- **Inline scripts prevent nonce-based CSP** — moving scripts to external files allows a strict policy without `'unsafe-inline'`
- **`eval()` is the worst offender** — it requires `'unsafe-eval'`, which undermines most XSS protection; use `JSON.parse` and `Function` constructors instead
- **CSP should be page-specific** — a single site-wide CSP often ends up too permissive because different pages load different resources
- **Strict CSP pages produce zero findings** — demonstrating the difference between a well-hardened page and an unprotected one

## Further Reading

- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Level 3 specification (W3C)](https://www.w3.org/TR/CSP3/)
