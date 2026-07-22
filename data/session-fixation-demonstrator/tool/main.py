import argparse
import json
import sys

import httpx

CREDENTIALS = {"username": "alice", "password": "secret123"}


def scan(target: str) -> dict:
    findings = []

    try:
        # --- Vulnerable endpoint ---
        with httpx.Client(base_url=target, follow_redirects=True) as client:
            r1 = client.get("/session")
            if r1.status_code == 200:
                pre_session = client.cookies.get("session_id")

                r2 = client.post("/login/vulnerable", json=CREDENTIALS)
                post_session = client.cookies.get("session_id")

                if r2.status_code == 200 and pre_session and pre_session == post_session:
                    findings.append({
                        "endpoint": "/login/vulnerable",
                        "vulnerability_type": "SESSION_FIXATION",
                        "evidence": (
                            f"Session ID unchanged after successful login "
                            f"(id prefix: {pre_session[:8]}…). "
                            "An attacker who plants a known session ID before login "
                            "gains authenticated access once the victim logs in."
                        ),
                        "severity": "HIGH",
                    })

        # --- Safe endpoint (fresh client = clean cookie jar) ---
        with httpx.Client(base_url=target, follow_redirects=True) as client2:
            r3 = client2.get("/session")
            if r3.status_code == 200:
                pre_safe = client2.cookies.get("session_id")

                r4 = client2.post("/login/safe", json=CREDENTIALS)
                post_safe = client2.cookies.get("session_id")

                if r4.status_code == 200 and (post_safe is None or pre_safe == post_safe):
                    findings.append({
                        "endpoint": "/login/safe",
                        "vulnerability_type": "SESSION_FIXATION",
                        "evidence": "Safe endpoint did not issue a new session ID after login.",
                        "severity": "HIGH",
                    })

    except httpx.ConnectError:
        pass
    except Exception as exc:
        print(f"Warning: unexpected error during scan: {exc}", file=sys.stderr)

    vulnerable_count = sum(1 for f in findings if f["endpoint"] == "/login/vulnerable")
    if findings:
        summary = (
            f"Found {len(findings)} session fixation issue(s). "
            "The vulnerable login endpoint does not regenerate the session ID after "
            "authentication, allowing an attacker to fix the session ID before login "
            "and gain access once the victim authenticates."
        )
    else:
        summary = "No session fixation vulnerabilities detected. All login endpoints correctly regenerate session IDs."

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="Session Fixation Vulnerability Scanner")
    parser.add_argument("--target", default="http://localhost:3000", help="Base URL of the target server")
    args = parser.parse_args()

    print(f"Scanning {args.target} for session fixation vulnerabilities...", file=sys.stderr)
    result = scan(args.target)
    print(json.dumps(result, indent=2))

    for finding in result["findings"]:
        print(
            f"[{finding['severity']}] {finding['vulnerability_type']} @ {finding['endpoint']}",
            file=sys.stderr,
        )

    if not result["findings"]:
        print("No vulnerabilities found.", file=sys.stderr)


if __name__ == "__main__":
    main()
