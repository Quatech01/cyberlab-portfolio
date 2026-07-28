"""Subdomain enumerator — wordlist-based subdomain discovery via DNS-over-HTTP."""

import argparse
import json
import sys

import httpx

# Common subdomain labels to probe. Covers generic services, management
# interfaces, dev/staging environments, infrastructure, and data stores.
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap",
    "webmail", "cpanel", "whm", "ns1", "ns2",
    "api", "api2", "api-v2", "gateway",
    "admin", "administrator", "portal", "dashboard", "console",
    "dev", "develop", "development",
    "staging", "stage", "uat", "qa", "test", "sandbox",
    "db", "database", "mysql", "postgres", "mongo",
    "internal", "intranet", "vpn", "remote",
    "backup", "archive", "old", "legacy",
    "cdn", "static", "assets", "media",
    "shop", "store", "pay", "payments", "checkout",
    "blog", "wiki", "docs", "support", "help",
    "m", "mobile", "app",
    "demo", "beta", "preview",
    "git", "svn", "ci", "jenkins", "build",
    "monitor", "status", "metrics", "prometheus", "grafana",
    "kibana", "elastic", "splunk",
    "mail2", "smtp2", "mx1", "mx2",
    "secure", "login", "auth", "sso", "oauth",
    "download", "upload", "files",
]

# Subdomain labels whose discovery warrants HIGH severity — management
# panels, dev/staging environments, and data stores are high-value targets.
SENSITIVE_SUBDOMAINS = {
    "admin", "administrator", "portal", "dashboard", "console",
    "dev", "develop", "development",
    "staging", "stage", "uat", "qa", "test", "sandbox",
    "internal", "intranet", "vpn", "remote",
    "db", "database", "mysql", "postgres", "mongo",
    "backup", "archive", "old", "legacy",
    "git", "svn", "ci", "jenkins", "build",
    "monitor", "metrics", "prometheus", "grafana",
    "kibana", "elastic", "splunk", "status",
}

# API gateway subdomains warrant MEDIUM severity — exposed but expected.
API_SUBDOMAINS = {"api", "api2", "api-v2", "gateway"}


def classify_severity(subdomain: str) -> str:
    if subdomain in SENSITIVE_SUBDOMAINS:
        return "HIGH"
    if subdomain in API_SUBDOMAINS:
        return "MEDIUM"
    return "LOW"


def enumerate_subdomains(
    target: str,
    domain: str,
    wordlist: list,
    timeout: float = 5.0,
) -> dict:
    findings = []
    errors = []

    try:
        with httpx.Client(base_url=target, timeout=timeout) as client:
            for sub in wordlist:
                fqdn = f"{sub}.{domain}"
                try:
                    r = client.get("/resolve", params={"name": fqdn})
                    if r.status_code == 200:
                        data = r.json()
                        findings.append(
                            {
                                "endpoint": fqdn,
                                "vulnerability_type": "subdomain_discovered",
                                "evidence": (
                                    f"Resolved to {data.get('address', 'unknown')}"
                                    f" (TTL {data.get('ttl', 0)}s)"
                                ),
                                "severity": classify_severity(sub),
                                "address": data.get("address"),
                            }
                        )
                except httpx.RequestError as exc:
                    errors.append(str(exc))
                    break  # server unreachable — stop probing remaining words
    except Exception as exc:
        errors.append(str(exc))

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    return {
        "target": target,
        "domain": domain,
        "words_probed": len(wordlist),
        "findings": findings,
        "summary": (
            f"Discovered {len(findings)} subdomain(s) for {domain}: "
            f"{high} HIGH, {medium} MEDIUM, {low} LOW severity."
            + (f" Errors: {'; '.join(errors)}" if errors else "")
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Wordlist-based subdomain enumerator")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the mock DNS resolver",
    )
    parser.add_argument(
        "--domain",
        default="example.com",
        help="Domain to enumerate subdomains for",
    )
    args = parser.parse_args()

    try:
        result = enumerate_subdomains(args.target, args.domain, DEFAULT_WORDLIST)
    except Exception as exc:
        result = {
            "target": args.target,
            "domain": args.domain,
            "words_probed": 0,
            "findings": [],
            "summary": f"Fatal error: {exc}",
        }

    print(json.dumps(result, indent=2))

    high_count = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    print(
        f"\n[subdomain-enumerator] {len(result['findings'])} subdomain(s) found, "
        f"{high_count} HIGH severity",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
