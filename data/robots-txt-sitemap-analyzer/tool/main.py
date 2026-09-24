import argparse
import json
import re
import sys
from xml.etree import ElementTree as ET

import httpx

SENSITIVE_PATTERNS = {
    "HIGH": [
        r"\.git",
        r"\.svn",
        r"\.hg",
        r"phpmyadmin",
        r"wp-admin",
        r"cpanel",
        r"webmin",
        r"server-status",
        r"server-info",
        r"\.env",
    ],
    "MEDIUM": [
        r"/admin(?:/|$)",
        r"/administrator",
        r"/backup",
        r"/config",
        r"/staging",
        r"/api/internal",
        r"/internal",
        r"/private",
        r"/secret",
    ],
    "LOW": [
        r"/dev(?:/|$)",
        r"/test(?:/|$)",
        r"/development",
        r"/debug",
        r"/sandbox",
    ],
}


def classify_path(path: str):
    path_lower = path.lower()
    for severity, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower):
                return severity, pattern
    return None


def fetch_robots(target: str, robots_path: str):
    url = target.rstrip("/") + robots_path
    try:
        r = httpx.get(url, follow_redirects=False, timeout=5)
    except (httpx.ConnectError, httpx.TimeoutException):
        return None, url
    if r.status_code != 200:
        return None, url
    return r.text, url


def parse_robots(text: str):
    disallowed = []
    sitemaps = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("disallow:"):
            path = stripped[9:].split("#")[0].strip()
            if path:
                disallowed.append(path)
        elif stripped.lower().startswith("sitemap:"):
            url = stripped[8:].strip()
            if url:
                sitemaps.append(url)
    return disallowed, sitemaps


def fetch_sitemap(url: str):
    try:
        r = httpx.get(url, follow_redirects=False, timeout=5)
    except (httpx.ConnectError, httpx.TimeoutException):
        return []
    if r.status_code != 200:
        return []
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return []
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = []
    for elem in root.findall("sm:url/sm:loc", ns):
        if elem.text:
            locs.append(elem.text)
    return locs


def extract_path(url: str) -> str:
    parts = url.split("/", 3)
    return "/" + parts[3] if len(parts) > 3 else "/"


def scan(target: str, robots_path: str = "/robots.txt") -> dict:
    findings = []

    text, robots_url = fetch_robots(target, robots_path)
    if text is None:
        return {
            "target": target,
            "findings": [],
            "summary": "robots.txt not found or server unreachable",
        }

    disallowed, sitemap_urls = parse_robots(text)

    for path in disallowed:
        result = classify_path(path)
        if result:
            severity, pattern = result
            findings.append(
                {
                    "endpoint": robots_url,
                    "vulnerability_type": "SENSITIVE_PATH_DISCLOSED",
                    "evidence": f"Disallow: {path} (pattern: {pattern})",
                    "severity": severity,
                }
            )

    for sitemap_url in sitemap_urls:
        locs = fetch_sitemap(sitemap_url)
        for loc in locs:
            path = extract_path(loc)
            result = classify_path(path)
            if result:
                severity, pattern = result
                findings.append(
                    {
                        "endpoint": sitemap_url,
                        "vulnerability_type": "SITEMAP_PATH_DISCLOSED",
                        "evidence": f"{loc} (path: {path}, pattern: {pattern})",
                        "severity": severity,
                    }
                )

    n_robots = sum(1 for f in findings if f["vulnerability_type"] == "SENSITIVE_PATH_DISCLOSED")
    n_sitemap = sum(1 for f in findings if f["vulnerability_type"] == "SITEMAP_PATH_DISCLOSED")
    summary = f"{n_robots} sensitive path(s) in robots.txt, {n_sitemap} sensitive URL(s) in sitemap(s)"

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="Robots.txt and Sitemap Analyzer")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--robots-path", default="/robots.txt")
    args = parser.parse_args()

    result = scan(args.target, args.robots_path)

    print(f"[+] Target: {result['target']}", file=sys.stderr)
    print(f"[+] {result['summary']}", file=sys.stderr)
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vulnerability_type']}: {f['evidence']}", file=sys.stderr)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
