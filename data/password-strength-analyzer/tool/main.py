import argparse
import json
import math
import re
import sys

import httpx

COMMON_PASSWORDS = {
    "password", "123456", "password123", "qwerty", "abc123",
    "letmein", "monkey", "1234567", "dragon", "master",
    "sunshine", "princess", "welcome", "shadow", "superman",
    "michael", "football", "iloveyou", "admin", "login",
    "hello", "charlie", "donald", "password1", "qwerty123",
    "111111", "1234567890", "123123", "admin123", "pass",
    "password!", "passw0rd", "p@ssword", "pa55word",
}

WEAK_TEST_PASSWORDS = [
    "123456",
    "password",
    "qwerty123",
    "abc",
    "letmein",
    "admin123",
]

STRONG_TEST_PASSWORDS = [
    "P@ssw0rd1234!",
    "Tr0ub4dor&3Xq",
    "C0rr3ct!H0rs3Bat",
]


def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", password):
        charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def analyze_locally(password: str) -> dict:
    entropy = calculate_entropy(password)
    is_common = password.lower() in COMMON_PASSWORDS
    keyboard_walks = ["qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz"]
    has_walk = any(w in password.lower() for w in keyboard_walks)
    leet_map = str.maketrans("@30175!", "aeoilsi")
    is_leet = password.lower().translate(leet_map) in COMMON_PASSWORDS

    issues = []
    if len(password) < 8:
        issues.append("too_short")
    if is_common:
        issues.append("common_password")
    if entropy < 30:
        issues.append("very_low_entropy")
    elif entropy < 50:
        issues.append("low_entropy")
    if has_walk:
        issues.append("keyboard_walk_pattern")
    if is_leet:
        issues.append("leetspeak_of_common_word")
    if not re.search(r"[A-Z]", password):
        issues.append("no_uppercase")
    if not re.search(r"[a-z]", password):
        issues.append("no_lowercase")
    if not re.search(r"[0-9]", password):
        issues.append("no_digit")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", password):
        issues.append("no_special_char")

    if entropy < 20:
        strength = "very_weak"
    elif entropy < 40:
        strength = "weak"
    elif entropy < 60:
        strength = "moderate"
    else:
        strength = "strong"

    return {
        "entropy_bits": round(entropy, 2),
        "is_common": is_common,
        "is_leet_common": is_leet,
        "has_keyboard_walk": has_walk,
        "issues": issues,
        "strength": strength,
    }


def probe_endpoint(client: httpx.Client, url: str, password: str, username_suffix: str) -> dict:
    import uuid
    username = f"probe_{username_suffix}_{uuid.uuid4().hex[:6]}"
    try:
        r = client.post(url, json={"username": username, "password": password}, timeout=5.0)
        return {"accepted": r.status_code == 201, "status_code": r.status_code}
    except Exception as exc:
        return {"accepted": False, "status_code": None, "error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer — tests password policy enforcement")
    parser.add_argument("--target", default="http://localhost:3000", help="Base URL of the demo server")
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    findings = []

    try:
        client = httpx.Client(timeout=10.0)

        # Reachability check — bail early with empty findings if server is down
        try:
            health = client.get(f"{base_url}/health", timeout=3.0)
            if health.status_code != 200:
                raise Exception(f"health check returned HTTP {health.status_code}")
        except Exception as exc:
            print(f"[!] Cannot reach target: {exc}", file=sys.stderr)
            out = {"target": base_url, "findings": [], "summary": f"Could not connect to {base_url}: {exc}"}
            print(json.dumps(out, indent=2))
            return

        # Fetch policy metadata
        unsafe_policy = {}
        safe_policy = {}
        try:
            resp = client.get(f"{base_url}/api/policy/unsafe")
            if resp.status_code == 200:
                unsafe_policy = resp.json()
            resp = client.get(f"{base_url}/api/policy/safe")
            if resp.status_code == 200:
                safe_policy = resp.json()
        except Exception:
            pass

        # Flag weak policy configuration
        if not unsafe_policy.get("blocks_common_passwords", True):
            findings.append({
                "endpoint": "/api/policy/unsafe",
                "vulnerability_type": "policy_allows_common_passwords",
                "evidence": (
                    f"Policy config exposes blocks_common_passwords=false, "
                    f"min_length={unsafe_policy.get('min_length', 'unknown')}, "
                    f"min_entropy_bits={unsafe_policy.get('min_entropy_bits', 0)}"
                ),
                "severity": "HIGH",
            })

        # Test weak passwords against the unsafe endpoint
        weak_accepted = []
        for pw in WEAK_TEST_PASSWORDS:
            result = probe_endpoint(client, f"{base_url}/api/register/unsafe", pw, "weak")
            if result["accepted"]:
                weak_accepted.append(pw)

        for pw in weak_accepted:
            local = analyze_locally(pw)
            findings.append({
                "endpoint": "/api/register/unsafe",
                "vulnerability_type": "weak_password_policy",
                "evidence": (
                    f"Accepted password '{pw}' — entropy: {local['entropy_bits']} bits, "
                    f"strength: {local['strength']}, issues: {', '.join(local['issues']) or 'none'}"
                ),
                "severity": "HIGH",
            })

        # Check whether safe endpoint incorrectly accepts weak passwords
        safe_accepts_weak = []
        for pw in WEAK_TEST_PASSWORDS:
            result = probe_endpoint(client, f"{base_url}/api/register/safe", pw, "safe_weak")
            if result["accepted"]:
                safe_accepts_weak.append(pw)

        if safe_accepts_weak:
            findings.append({
                "endpoint": "/api/register/safe",
                "vulnerability_type": "strong_policy_bypass",
                "evidence": f"Strong policy endpoint accepted weak password(s): {safe_accepts_weak}",
                "severity": "CRITICAL",
            })

        # Verify safe endpoint accepts genuinely strong passwords (sanity check)
        safe_rejects_strong = []
        for pw in STRONG_TEST_PASSWORDS:
            result = probe_endpoint(client, f"{base_url}/api/register/safe", pw, "safe_strong")
            if not result["accepted"]:
                safe_rejects_strong.append(pw)

        if safe_rejects_strong:
            findings.append({
                "endpoint": "/api/register/safe",
                "vulnerability_type": "policy_too_restrictive",
                "evidence": f"Safe endpoint rejected strong password(s): {safe_rejects_strong}",
                "severity": "LOW",
            })

        # Add informational local analysis for each weak password
        for pw in WEAK_TEST_PASSWORDS:
            local = analyze_locally(pw)
            if local["issues"]:
                findings.append({
                    "endpoint": "local_analysis",
                    "vulnerability_type": "weak_password_in_test_set",
                    "evidence": (
                        f"'{pw}': entropy={local['entropy_bits']} bits, "
                        f"strength={local['strength']}, issues={local['issues']}"
                    ),
                    "severity": "INFO",
                })

        high_count = len([f for f in findings if f["severity"] in ("HIGH", "CRITICAL")])
        summary = (
            f"Scanned {base_url}: {high_count} high/critical policy issue(s) detected. "
            f"/api/register/unsafe accepted {len(weak_accepted)}/{len(WEAK_TEST_PASSWORDS)} weak test passwords. "
            f"/api/register/safe {'correctly rejected all weak passwords' if not safe_accepts_weak else 'FAILED — accepted weak passwords'}."
        )

    except Exception as exc:
        print(f"[!] Cannot reach target: {exc}", file=sys.stderr)
        out = {"target": base_url, "findings": [], "summary": f"Could not connect to {base_url}: {exc}"}
        print(json.dumps(out, indent=2))
        return

    out = {"target": base_url, "findings": findings, "summary": summary}
    print(json.dumps(out, indent=2))

    print(f"\n[Password Strength Analyzer] Target: {base_url}", file=sys.stderr)
    print(f"[Password Strength Analyzer] Findings: {len(findings)} total, {high_count} high/critical", file=sys.stderr)


if __name__ == "__main__":
    main()
