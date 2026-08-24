#!/usr/bin/env python3
"""CORS Misconfiguration Scanner — detects dangerous Cross-Origin Resource Sharing policies."""

import argparse
import json
import sys

import httpx


def probe(client: httpx.Client, base_url: str, path: str, origin: str) -> dict | None:
    try:
        r = client.get(
            f"{base_url}{path}",
            headers={"Origin": origin},
            follow_redirects=False,
            timeout=5.0,
        )
        return {
            "status": r.status_code,
            "acao": r.headers.get("access-control-allow-origin", ""),
            "acac": r.headers.get("access-control-allow-credentials", "").lower(),
        }
    except httpx.ConnectError:
        return None
    except Exception as exc:
        return {"error": str(exc)}


def analyze(target: str) -> dict:
    findings = []

    try:
        with httpx.Client() as client:
            # Bail out early if server is unreachable
            try:
                client.get(f"{target}/health", timeout=5.0)
            except httpx.ConnectError:
                return {
                    "target": target,
                    "findings": [],
                    "summary": "Server unreachable — no findings",
                }

            # --- Check 1: wildcard ACAO ---
            r1 = probe(client, target, "/api/unsafe/data", "http://evil.attacker.com")
            if r1 and r1.get("acao") == "*":
                findings.append(
                    {
                        "endpoint": "/api/unsafe/data",
                        "vulnerability_type": "CORS_WILDCARD",
                        "evidence": (
                            "Access-Control-Allow-Origin: * — any origin can read this "
                            "response. Harmless for fully public data, but becomes critical "
                            "if authentication is ever added."
                        ),
                        "severity": "MEDIUM",
                    }
                )
                print("[WARN] /api/unsafe/data — CORS wildcard (*) detected", file=sys.stderr)

            # --- Check 2: reflected origin with credentials ---
            attacker = "http://evil.attacker.com"
            r2 = probe(client, target, "/api/leak/profile", attacker)
            if r2 and r2.get("acao") == attacker and r2.get("acac") == "true":
                findings.append(
                    {
                        "endpoint": "/api/leak/profile",
                        "vulnerability_type": "CORS_REFLECTED_ORIGIN_WITH_CREDENTIALS",
                        "evidence": (
                            f"Access-Control-Allow-Origin: {attacker} (reflected), "
                            "Access-Control-Allow-Credentials: true — "
                            "any attacker page can make credentialed cross-origin requests "
                            "and read the full response including session cookies."
                        ),
                        "severity": "HIGH",
                    }
                )
                print(
                    "[CRIT] /api/leak/profile — origin reflected + credentials enabled",
                    file=sys.stderr,
                )

            # --- Check 3: null origin with credentials ---
            r3 = probe(client, target, "/api/null/upload", "null")
            if r3 and r3.get("acao") == "null" and r3.get("acac") == "true":
                findings.append(
                    {
                        "endpoint": "/api/null/upload",
                        "vulnerability_type": "CORS_NULL_ORIGIN_WITH_CREDENTIALS",
                        "evidence": (
                            "Access-Control-Allow-Origin: null, "
                            "Access-Control-Allow-Credentials: true — "
                            "sandboxed iframes (data: URIs, srcdoc) send Origin: null and "
                            "can therefore read credentialed responses."
                        ),
                        "severity": "HIGH",
                    }
                )
                print(
                    "[CRIT] /api/null/upload — null origin allowed with credentials",
                    file=sys.stderr,
                )

            # --- Check 4: safe allowlist endpoint (false-positive canary) ---
            r4 = probe(client, target, "/api/safe/account", "http://evil.attacker.com")
            if r4:
                acao = r4.get("acao", "")
                if acao == "http://evil.attacker.com" or acao == "*":
                    findings.append(
                        {
                            "endpoint": "/api/safe/account",
                            "vulnerability_type": "CORS_ALLOWLIST_BYPASS",
                            "evidence": f"Allowlist endpoint reflected attacker origin: {acao}",
                            "severity": "HIGH",
                        }
                    )
                else:
                    print(
                        "[OK]   /api/safe/account — allowlist enforced, attacker origin rejected",
                        file=sys.stderr,
                    )

    except Exception as exc:
        return {"target": target, "findings": [], "summary": f"Scanner error: {exc}"}

    vuln_count = len(findings)
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")

    if findings:
        summary = (
            f"Found {vuln_count} CORS misconfiguration(s) across {target} — "
            f"{high_count} HIGH severity. "
            "Reflected-origin + credentials and null-origin + credentials allow "
            "attacker-controlled pages to silently read authenticated API responses."
        )
    else:
        summary = f"No CORS misconfigurations found on {target}."

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Scanner")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    result = analyze(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
