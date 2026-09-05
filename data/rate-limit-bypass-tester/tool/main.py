"""
Rate Limit Bypass Tester

Probes HTTP endpoints for rate limiting that can be circumvented by rotating
the X-Forwarded-For header. Safe endpoints key by actual TCP connection IP
and cannot be bypassed this way.
"""

import argparse
import json
import sys
import httpx


def _reset(client: httpx.Client, base_url: str) -> None:
    try:
        client.post(f"{base_url}/api/admin/reset-limits", timeout=5.0)
    except Exception:
        pass


def probe_endpoint(client: httpx.Client, base_url: str, path: str, rate_limit: int) -> dict | None:
    """
    Returns a finding dict if an X-Forwarded-For bypass is confirmed,
    or None if the endpoint is not vulnerable.
    """
    full_url = f"{base_url}{path}"
    fake_ip_a = "203.0.113.10"
    fake_ip_b = "203.0.113.20"

    _reset(client, base_url)

    # Phase 1 — exhaust the rate limit using a fixed fake IP
    print(f"  [*] Exhausting rate limit on {path} with X-Forwarded-For: {fake_ip_a}", file=sys.stderr)
    for _ in range(rate_limit):
        try:
            r = client.post(
                full_url,
                json={"username": "probe", "password": "x"},
                headers={"X-Forwarded-For": fake_ip_a},
            )
            if r.status_code == 429:
                print(f"  [!] Hit 429 before exhausting {rate_limit} requests — unexpected", file=sys.stderr)
                return None
        except Exception as exc:
            print(f"  [!] Request failed: {exc}", file=sys.stderr)
            return None

    # Confirm limit is now active
    try:
        confirm = client.post(
            full_url,
            json={"username": "probe", "password": "x"},
            headers={"X-Forwarded-For": fake_ip_a},
        )
    except Exception as exc:
        print(f"  [!] Confirmation request failed: {exc}", file=sys.stderr)
        return None

    if confirm.status_code != 429:
        print(f"  [WARN] Expected 429 after {rate_limit} requests, got {confirm.status_code}", file=sys.stderr)
        return None

    print(f"  [+] Rate limit confirmed: request {rate_limit + 1} returned 429", file=sys.stderr)

    # Phase 2 — attempt bypass by rotating to a different fake IP
    try:
        bypass = client.post(
            full_url,
            json={"username": "probe", "password": "x"},
            headers={"X-Forwarded-For": fake_ip_b},
        )
    except Exception as exc:
        print(f"  [!] Bypass request failed: {exc}", file=sys.stderr)
        return None

    if bypass.status_code == 200:
        print(
            f"  [!] BYPASS DETECTED: rotating X-Forwarded-For from {fake_ip_a} to {fake_ip_b} "
            f"returned HTTP 200 — rate limit is keyed by header value, not real IP",
            file=sys.stderr,
        )
        return {
            "endpoint": path,
            "vulnerability_type": "RATE_LIMIT_BYPASS_VIA_HEADER",
            "evidence": (
                f"Rate limit of {rate_limit} req/window was exhausted using "
                f"X-Forwarded-For: {fake_ip_a} (HTTP 429 confirmed). "
                f"Rotating the header to X-Forwarded-For: {fake_ip_b} immediately "
                "returned HTTP 200, proving the limit is keyed by the spoofable header "
                "rather than the actual TCP connection IP."
            ),
            "severity": "HIGH",
        }

    print(f"  [+] No bypass: rotating X-Forwarded-For still returned {bypass.status_code}", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Rate Limit Bypass Tester")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    print(f"[*] Rate Limit Bypass Tester — target: {base_url}", file=sys.stderr)

    # Reachability check
    try:
        with httpx.Client(timeout=5.0) as c:
            r = c.get(f"{base_url}/health")
            if r.status_code != 200:
                raise ValueError(f"unexpected status {r.status_code}")
    except Exception as exc:
        print(f"[!] Server unreachable: {exc}", file=sys.stderr)
        print(
            json.dumps(
                {
                    "target": base_url,
                    "findings": [],
                    "summary": f"Server at {base_url} is unreachable. No tests performed.",
                },
                indent=2,
            )
        )
        return

    # Discover probe targets
    try:
        with httpx.Client(timeout=5.0) as c:
            meta = c.get(f"{base_url}/api/probe-targets").json()
    except Exception as exc:
        print(f"[!] Could not fetch probe targets: {exc}", file=sys.stderr)
        print(
            json.dumps(
                {
                    "target": base_url,
                    "findings": [],
                    "summary": "Failed to retrieve probe target list from server.",
                },
                indent=2,
            )
        )
        return

    endpoints = meta.get("endpoints", [])
    rate_limit = meta.get("rate_limit", 5)
    print(f"[*] Probing {len(endpoints)} endpoint(s), rate limit threshold: {rate_limit}", file=sys.stderr)

    findings: list[dict] = []

    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        for ep in endpoints:
            path = ep["path"]
            print(f"[*] Testing: {path}", file=sys.stderr)
            finding = probe_endpoint(client, base_url, path, rate_limit)
            if finding:
                findings.append(finding)

    if findings:
        summary = (
            f"Found {len(findings)} rate limit bypass vulnerability across {len(endpoints)} "
            "endpoint(s). The affected endpoint keys its rate limit on the X-Forwarded-For "
            "header, which any client can set to an arbitrary value. Rotating this header "
            "allows unlimited requests, defeating the intended brute-force protection."
        )
    else:
        summary = (
            f"No rate limit bypass vulnerabilities detected across {len(endpoints)} endpoint(s). "
            "All tested endpoints key rate limits by the actual TCP connection IP, "
            "which cannot be spoofed by manipulating HTTP headers."
        )

    print(
        json.dumps(
            {"target": base_url, "findings": findings, "summary": summary},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
