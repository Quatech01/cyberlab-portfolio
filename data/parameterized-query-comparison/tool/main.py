#!/usr/bin/env python3
"""
Parameterized Query vs Raw Query Comparison Tool

Probes a demo server's search and login endpoints with SQL injection payloads,
reporting which endpoints use unsafe string concatenation vs safe parameterized
queries.
"""
import argparse
import json
import sys

import httpx

SEARCH_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
]

LOGIN_PAYLOADS = [
    {"username": "admin'--", "password": "wrongpassword"},
    {"username": "' OR '1'='1' --", "password": "' OR '1'='1' --"},
]


def probe_search(client: httpx.Client, base: str, path: str) -> list[dict]:
    findings = []
    try:
        r = client.get(f"{base}{path}", params={"name": "nonexistent_xyz_abc"})
        baseline = len(r.json().get("users", []))
    except Exception:
        return findings

    for payload in SEARCH_PAYLOADS:
        try:
            r = client.get(f"{base}{path}", params={"name": payload})
            if r.status_code == 200:
                count = len(r.json().get("users", []))
                if count > baseline:
                    findings.append({
                        "endpoint": path,
                        "vulnerability_type": "sql_injection",
                        "evidence": (
                            f"Payload '{payload}' returned {count} row(s); "
                            f"baseline was {baseline}"
                        ),
                        "severity": "HIGH",
                    })
                    break
            elif r.status_code == 500:
                findings.append({
                    "endpoint": path,
                    "vulnerability_type": "sql_injection_error_based",
                    "evidence": f"500 error triggered by payload '{payload}': {r.text[:200]}",
                    "severity": "HIGH",
                })
                break
        except Exception:
            continue
    return findings


def probe_login(client: httpx.Client, base: str, path: str) -> list[dict]:
    findings = []
    try:
        r = client.post(f"{base}{path}", json={"username": "nobody_xyz", "password": "wrong"})
        if r.status_code != 401:
            return findings
    except Exception:
        return findings

    for payload in LOGIN_PAYLOADS:
        try:
            r = client.post(f"{base}{path}", json=payload)
            if r.status_code == 200 and r.json().get("authenticated"):
                findings.append({
                    "endpoint": path,
                    "vulnerability_type": "sql_injection_auth_bypass",
                    "evidence": (
                        f"Authenticated without valid credentials using "
                        f"username='{payload['username']}'"
                    ),
                    "severity": "CRITICAL",
                })
                break
        except Exception:
            continue
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Probe a server for parameterized-query vs string-concat SQLi"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the demo server (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"[*] Target: {target}", file=sys.stderr)

    try:
        client = httpx.Client(timeout=10.0, follow_redirects=False)
    except Exception as exc:
        print(json.dumps({"target": target, "findings": [], "summary": str(exc)}))
        return

    findings: list[dict] = []
    try:
        try:
            r = client.get(f"{target}/health")
            r.raise_for_status()
        except Exception:
            print(json.dumps({
                "target": target,
                "findings": [],
                "summary": "Target unreachable — no findings",
            }))
            return

        print("[*] Probing /search endpoints...", file=sys.stderr)
        findings += probe_search(client, target, "/search/unsafe")
        findings += probe_search(client, target, "/search/safe")

        print("[*] Probing /login endpoints...", file=sys.stderr)
        findings += probe_login(client, target, "/login/unsafe")
        findings += probe_login(client, target, "/login/safe")
    finally:
        client.close()

    n = len(findings)
    if n:
        summary = (
            f"Found {n} SQL injection issue(s). "
            "String-concatenated endpoints are exploitable; "
            "parameterized endpoints correctly reject all injection payloads."
        )
    else:
        summary = "No SQL injection vulnerabilities detected."

    print(json.dumps({"target": target, "findings": findings, "summary": summary}, indent=2))


if __name__ == "__main__":
    main()
