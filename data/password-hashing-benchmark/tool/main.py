"""
Password Hashing Benchmark — security scanner tool

Connects to the demo server, retrieves benchmark timing for each password
hashing algorithm, attempts a dictionary attack against the stored hashes
of any algorithm flagged as unsafe, and reports structured JSON findings.

Usage:
    python tool/main.py --target http://localhost:3000

Output:
    stdout — JSON report {target, findings, summary}
    stderr — human-readable progress and summary
"""

import argparse
import json
import sys

import httpx

# Common password dictionary used for dictionary-attack demonstration.
# "password123" appears near the top — it matches the demo server's pre-seeded hash.
COMMON_PASSWORDS = [
    "password",
    "password123",
    "123456",
    "letmein",
    "admin",
    "qwerty",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "abc123",
    "111111",
    "sunshine",
    "princess",
    "iloveyou",
    "summer",
    "chocolate",
    "soccer",
    "george",
    "batman",
    "trustno1",
    "shadow",
    "superman",
    "michael",
    "football",
]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def scan(target: str) -> dict:
    target = target.rstrip("/")
    findings = []
    benchmark_data = {}

    # ── Step 1: fetch benchmark timings ──────────────────────────────────────
    eprint(f"[*] Connecting to {target}")
    try:
        resp = httpx.get(f"{target}/benchmark", timeout=30.0)
        resp.raise_for_status()
        benchmark_data = resp.json()
    except Exception as exc:
        eprint(f"[!] Server unreachable: {exc}")
        return {
            "target": target,
            "findings": [],
            "summary": f"Scan aborted — server unreachable at {target}: {exc}",
        }

    eprint(f"[*] Benchmark results:")
    for algo, data in benchmark_data.items():
        label = "UNSAFE" if not data.get("safe", True) else "safe"
        eprint(f"    {algo:8s}  {data['time_ms']:>8.3f} ms  [{label}]")

    # ── Step 2: fetch pre-seeded hashes ──────────────────────────────────────
    try:
        resp = httpx.get(f"{target}/hashes", timeout=10.0)
        resp.raise_for_status()
        hashes = resp.json()
    except Exception as exc:
        eprint(f"[!] Failed to fetch hashes: {exc}")
        hashes = {}

    # ── Step 3: analyse each algorithm ───────────────────────────────────────
    safe_algos = []
    for algo, data in benchmark_data.items():
        if data.get("safe", True):
            safe_algos.append(algo)
            eprint(f"[+] {algo}: safe — {data['reason'][:60]}...")
            continue

        # Unsafe algorithm: attempt a dictionary crack to quantify the risk
        eprint(f"[-] {algo}: UNSAFE — attempting dictionary attack …")

        stored_hash = hashes.get(algo)
        crack_result = {"cracked": False, "attempts": 0, "time_ms": 0}

        if stored_hash:
            body: dict = {
                "algorithm": algo,
                "hash": stored_hash,
                "wordlist": COMMON_PASSWORDS,
            }
            if algo == "scrypt":
                body["scrypt_salt"] = hashes.get("scrypt_salt")
            try:
                resp = httpx.post(f"{target}/crack", json=body, timeout=60.0)
                resp.raise_for_status()
                crack_result = resp.json()
            except Exception as exc:
                eprint(f"[!] Crack request failed: {exc}")

        evidence_parts = [
            f"{algo.upper()} hashes in {data['time_ms']:.4f} ms per operation.",
            data["reason"],
        ]
        if crack_result.get("cracked"):
            pw = crack_result["password"]
            ms = crack_result["time_ms"]
            attempts = crack_result["attempts"]
            evidence_parts.append(
                f'Dictionary attack recovered password "{pw}" '
                f"in {ms:.2f} ms after {attempts} attempt(s)."
            )
            eprint(
                f"[!] CRACKED: '{pw}' recovered in {ms:.2f} ms "
                f"({attempts} attempt(s))"
            )
        else:
            evidence_parts.append(
                "Password not in test wordlist, but the fast hash speed means "
                "real-world attackers can try billions of candidates per second."
            )

        findings.append(
            {
                "endpoint": f"/hashes#{algo}",
                "vulnerability_type": "FAST_HASH_ALGORITHM",
                "evidence": " ".join(evidence_parts),
                "severity": "HIGH",
            }
        )

    # ── Step 4: compose summary ───────────────────────────────────────────────
    if findings:
        unsafe_list = ", ".join(
            f["endpoint"].split("#")[1] for f in findings
        )
        safe_list = ", ".join(safe_algos) if safe_algos else "none"
        summary = (
            f"{len(findings)} vulnerability(s) found. "
            f"Unsafe algorithms: {unsafe_list}. "
            f"Safe algorithms (no findings): {safe_list}. "
            f"Replace fast hashes with bcrypt (cost ≥12), scrypt, or argon2id."
        )
    else:
        summary = (
            "No vulnerabilities found. All detected algorithms are "
            "purpose-built, slow password hashing functions."
        )

    eprint(f"\n[*] Summary: {summary}")
    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(
        description="Password Hashing Benchmark — identifies fast hash algorithms used for password storage"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the demo server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    result = scan(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
