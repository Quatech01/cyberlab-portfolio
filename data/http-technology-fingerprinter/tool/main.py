import argparse
import json
import re
import sys

import httpx

RULES = [
    {
        "technology": "WordPress",
        "checks": [
            {
                "type": "header",
                "header": "x-powered-by",
                "pattern": r"PHP/",
                "evidence_tpl": "X-Powered-By header reveals PHP runtime: {value}",
            },
            {
                "type": "header",
                "header": "server",
                "pattern": r"Apache",
                "evidence_tpl": "Server header reveals Apache httpd: {value}",
            },
            {
                "type": "cookie",
                "pattern": r"wordpress_logged_in",
                "evidence_tpl": "Cookie 'wordpress_logged_in' is WordPress's default authenticated session cookie",
            },
            {
                "type": "body",
                "pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress',
                "evidence_tpl": "Meta generator tag explicitly identifies WordPress CMS version",
            },
            {
                "type": "body",
                "pattern": r"/wp-content/",
                "evidence_tpl": "Path '/wp-content/' is exclusive to WordPress plugin and theme assets",
            },
        ],
        "severity": "MEDIUM",
        "vulnerability_type": "technology_disclosure",
        "min_matches": 2,
    },
    {
        "technology": "React",
        "checks": [
            {
                "type": "header",
                "header": "x-powered-by",
                "pattern": r"^Express$",
                "evidence_tpl": "X-Powered-By: Express is the default Express.js server header",
            },
            {
                "type": "body",
                "pattern": r'data-reactroot',
                "evidence_tpl": "Attribute 'data-reactroot' is injected by React's server-side renderer",
            },
            {
                "type": "body",
                "pattern": r"/static/js/[^\"']+\.chunk\.js",
                "evidence_tpl": "Script path '/static/js/*.chunk.js' matches Create React App's code-split output",
            },
        ],
        "severity": "LOW",
        "vulnerability_type": "technology_disclosure",
        "min_matches": 2,
    },
    {
        "technology": "Django",
        "checks": [
            {
                "type": "header",
                "header": "server",
                "pattern": r"gunicorn",
                "evidence_tpl": "Server header reveals gunicorn WSGI server, commonly deployed with Django: {value}",
            },
            {
                "type": "header",
                "header": "x-frame-options",
                "pattern": r"^SAMEORIGIN$",
                "evidence_tpl": "X-Frame-Options: SAMEORIGIN is set by Django's XFrameOptionsMiddleware by default",
            },
            {
                "type": "cookie",
                "pattern": r"^csrftoken$",
                "evidence_tpl": "Cookie named 'csrftoken' is Django's default CSRF cookie name (set by CsrfViewMiddleware)",
            },
            {
                "type": "body",
                "pattern": r'name=["\']csrfmiddlewaretoken["\']',
                "evidence_tpl": "Hidden field 'csrfmiddlewaretoken' is Django's default CSRF form field name",
            },
        ],
        "severity": "MEDIUM",
        "vulnerability_type": "technology_disclosure",
        "min_matches": 2,
    },
    {
        "technology": "Ruby on Rails",
        "checks": [
            {
                "type": "header",
                "header": "x-runtime",
                "pattern": r"^\d+\.\d+$",
                "evidence_tpl": "X-Runtime header (response time in seconds) is added by Rails' Rack::Runtime middleware: {value}s",
            },
            {
                "type": "header",
                "header": "x-request-id",
                "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "evidence_tpl": "X-Request-Id UUID header is added by Rails' ActionDispatch::RequestId middleware",
            },
            {
                "type": "cookie",
                "pattern": r"^_\w+_session$",
                "evidence_tpl": "Cookie name matching '_<app>_session' follows Rails' default session cookie naming convention",
            },
            {
                "type": "body",
                "pattern": r'name=["\']authenticity_token["\']',
                "evidence_tpl": "Hidden field 'authenticity_token' is Rails' CSRF token field name (set by form_with helper)",
            },
        ],
        "severity": "MEDIUM",
        "vulnerability_type": "technology_disclosure",
        "min_matches": 2,
    },
    {
        "technology": "Next.js",
        "checks": [
            {
                "type": "header",
                "header": "x-powered-by",
                "pattern": r"Next\.js",
                "evidence_tpl": "X-Powered-By header explicitly identifies Next.js framework",
            },
            {
                "type": "body",
                "pattern": r"/_next/static/",
                "evidence_tpl": "Path '/_next/static/' is Next.js's reserved static asset namespace",
            },
            {
                "type": "body",
                "pattern": r'id=["\']__NEXT_DATA__["\']',
                "evidence_tpl": "Script tag id='__NEXT_DATA__' is Next.js's server-side props injection mechanism",
            },
        ],
        "severity": "LOW",
        "vulnerability_type": "technology_disclosure",
        "min_matches": 2,
    },
]


def parse_cookies(response: httpx.Response) -> dict:
    cookies = {}
    for header_name, header_value in response.headers.items():
        if header_name.lower() == "set-cookie":
            first_part = header_value.split(";")[0].strip()
            if "=" in first_part:
                cookie_name = first_part.split("=")[0].strip()
                if cookie_name:
                    cookies[cookie_name] = True
    return cookies


def analyze_endpoint(base_url: str, path: str, client: httpx.Client) -> list:
    url = base_url.rstrip("/") + path
    try:
        r = client.get(url, follow_redirects=False, timeout=5.0)
    except Exception as exc:
        print(f"  [warn] {url}: {exc}", file=sys.stderr)
        return []

    headers = r.headers
    body = r.text
    cookies = parse_cookies(r)

    findings = []
    for rule in RULES:
        matched_evidences = []

        for check in rule["checks"]:
            hit = False
            if check["type"] == "header":
                val = headers.get(check["header"], "")
                if val and re.search(check["pattern"], val, re.IGNORECASE):
                    ev = check["evidence_tpl"].replace("{value}", val)
                    matched_evidences.append(ev)
                    hit = True
            elif check["type"] == "cookie":
                for cname in cookies:
                    if re.search(check["pattern"], cname):
                        matched_evidences.append(check["evidence_tpl"])
                        hit = True
                        break
            elif check["type"] == "body":
                if re.search(check["pattern"], body, re.IGNORECASE | re.DOTALL):
                    matched_evidences.append(check["evidence_tpl"])
                    hit = True

            _ = hit  # suppress unused warning

        if len(matched_evidences) >= rule["min_matches"]:
            findings.append(
                {
                    "endpoint": path,
                    "vulnerability_type": rule["vulnerability_type"],
                    "evidence": "; ".join(matched_evidences),
                    "severity": rule["severity"],
                    "technology": rule["technology"],
                }
            )

    return findings


def scan(target: str) -> dict:
    findings = []

    with httpx.Client() as client:
        try:
            r = client.get(target.rstrip("/") + "/targets", timeout=5.0)
            endpoints = r.json().get("endpoints", [])
        except Exception as exc:
            print(f"[error] Cannot connect to {target}: {exc}", file=sys.stderr)
            return {
                "target": target,
                "findings": [],
                "summary": f"Could not connect to server at {target}",
            }

        for path in endpoints:
            print(f"[scan] {path}", file=sys.stderr)
            findings.extend(analyze_endpoint(target, path, client))

    detected_techs = list({f["technology"] for f in findings})
    clean_count = len(endpoints) - len(findings)

    if findings:
        summary = (
            f"Detected technology fingerprints on {len(findings)} endpoint(s): "
            f"{', '.join(sorted(detected_techs))}. "
            f"{clean_count} endpoint(s) revealed no identifying information."
        )
    else:
        summary = "No technology fingerprints detected on any endpoint."

    return {
        "target": target,
        "findings": findings,
        "summary": summary,
    }


def main():
    parser = argparse.ArgumentParser(description="HTTP Technology Fingerprinter")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    result = scan(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
