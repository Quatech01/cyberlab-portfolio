import argparse
import json
import re
import sys
from email import message_from_string

import httpx


def parse_auth_results(auth_header: str) -> dict:
    results = {}
    if not auth_header:
        return results

    for match in re.finditer(r"(spf|dkim|dmarc)=(\w+)", auth_header, re.IGNORECASE):
        results[match.group(1).lower()] = match.group(2).lower()

    m = re.search(r"smtp\.mailfrom=([^\s;]+)", auth_header, re.IGNORECASE)
    if m:
        results["envelope_from"] = m.group(1)

    m = re.search(r"header\.from=([^\s;)]+)", auth_header, re.IGNORECASE)
    if m:
        results["header_from"] = m.group(1)

    m = re.search(r"\(p=(\w+)", auth_header, re.IGNORECASE)
    if m:
        results["dmarc_policy"] = m.group(1).lower()

    return results


def extract_domain(address: str) -> str:
    m = re.search(r"@([\w.-]+)", address)
    return m.group(1).lower() if m else ""


def analyze_headers(sample_id: str, raw_headers: str) -> list:
    findings = []
    msg = message_from_string(raw_headers + "\n\n")

    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    auth_results = msg.get("Authentication-Results", "")

    from_domain = extract_domain(from_header)
    envelope_domain = extract_domain(return_path)

    if not auth_results:
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "missing_email_authentication",
            "evidence": (
                f"No Authentication-Results header present. SPF, DKIM, and DMARC "
                f"cannot be verified for mail claiming to be from <{from_header}>."
            ),
            "severity": "MEDIUM",
        })
        return findings

    auth = parse_auth_results(auth_results)

    if auth.get("spf") in ("fail", "softfail", "none"):
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "spf_failure",
            "evidence": (
                f"SPF result: {auth.get('spf', 'unknown')}. "
                f"Envelope sender <{auth.get('envelope_from', 'unknown')}> is not "
                f"authorised to send on behalf of the From domain ({from_domain})."
            ),
            "severity": "HIGH",
        })

    auth_header_from = auth.get("header_from", "")
    if auth_header_from and from_domain and auth_header_from != from_domain:
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "email_spoofing",
            "evidence": (
                f"From domain ({from_domain}) does not match the authenticated "
                f"header.from domain ({auth_header_from}). Classic display-name spoofing."
            ),
            "severity": "HIGH",
        })
    elif (
        envelope_domain
        and from_domain
        and envelope_domain != from_domain
        and auth.get("dmarc") in ("fail", "none", None)
    ):
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "email_spoofing",
            "evidence": (
                f"From domain ({from_domain}) does not match envelope sender "
                f"({envelope_domain}) and DMARC did not pass."
            ),
            "severity": "HIGH",
        })

    if auth.get("dmarc") == "fail":
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "dmarc_failure",
            "evidence": (
                f"DMARC validation failed for header.from={auth.get('header_from', from_domain)}. "
                f"Mail bypasses the domain owner's enforcement policy."
            ),
            "severity": "HIGH",
        })

    if auth.get("dmarc") == "pass" and auth.get("dmarc_policy") == "none":
        findings.append({
            "endpoint": f"/samples/{sample_id}",
            "vulnerability_type": "dmarc_policy_none",
            "evidence": (
                "DMARC policy is p=none (monitoring only). Spoofed emails from this "
                "domain are reported but never quarantined or rejected by receiving servers."
            ),
            "severity": "MEDIUM",
        })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Email Header Analyzer — inspect email headers for authentication failures and spoofing indicators"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Target server URL (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    all_findings = []
    summary = ""

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{target}/samples")
            resp.raise_for_status()
            samples = resp.json().get("samples", [])

        print(f"[*] Found {len(samples)} email header samples to analyse", file=sys.stderr)

        with httpx.Client(timeout=10.0) as client:
            for sample in samples:
                sid = sample["id"]
                print(f"[*] Analysing: {sid}", file=sys.stderr)
                try:
                    resp = client.get(f"{target}/samples/{sid}")
                    resp.raise_for_status()
                    raw_headers = resp.json().get("headers", "")
                    findings = analyze_headers(sid, raw_headers)
                    all_findings.extend(findings)
                    if findings:
                        for f in findings:
                            print(f"  [!] {f['vulnerability_type']} ({f['severity']})", file=sys.stderr)
                    else:
                        print("  [+] Clean — no issues found", file=sys.stderr)
                except Exception as exc:
                    print(f"  [-] Error analysing {sid}: {exc}", file=sys.stderr)

        flagged = len({f["endpoint"] for f in all_findings})
        summary = (
            f"Analysed {len(samples)} email header samples; "
            f"{flagged}/{len(samples)} had findings. "
            f"{len(all_findings)} total finding(s) detected."
        )

    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException):
        summary = f"Cannot connect to {target} — server unreachable."
        print(f"[-] {summary}", file=sys.stderr)
    except Exception as exc:
        summary = f"Unexpected error: {exc}"
        print(f"[-] {summary}", file=sys.stderr)

    print(json.dumps({"target": target, "findings": all_findings, "summary": summary}, indent=2))


if __name__ == "__main__":
    main()
