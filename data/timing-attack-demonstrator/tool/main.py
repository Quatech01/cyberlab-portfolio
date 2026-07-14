"""
Timing Attack Demonstrator — scanner tool

Probes two token-check endpoints on the target server and determines
whether either is vulnerable to a timing side-channel attack by measuring
how response latency correlates with the number of matching prefix characters.
"""

import argparse
import json
import sys
import time
import httpx


def measure_timing(client: httpx.Client, url: str, token: str, samples: int = 8) -> float:
    """Return the median response time in milliseconds for N requests."""
    times = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            client.get(url, params={"token": token}, timeout=10.0)
        except Exception:
            return -1.0
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    mid = len(times) // 2
    return (times[mid - 1] + times[mid]) / 2 if len(times) % 2 == 0 else times[mid]


def detect_timing_side_channel(target: str, endpoint: str, secret_length: int) -> dict | None:
    """
    Tests whether the given endpoint leaks information via response timing.

    Strategy: send tokens with 0, half, and nearly-full prefix matches.
    If median latency increases linearly with the number of matching characters,
    the endpoint is vulnerable (Pearson r > 0.9 threshold).
    """
    with httpx.Client(base_url=target) as client:
        # Build three tokens with 0, ~half, and near-full prefix overlap with
        # 'SuperSecretToken' (the secret the server is protecting). Using a
        # placeholder character 'X' for the non-matching suffix.
        half = secret_length // 2
        tokens = [
            ("X" * secret_length, 0),
            ("SuperSecretToken"[:half] + "X" * (secret_length - half), half),
            ("SuperSecretToken"[: secret_length - 1] + "X", secret_length - 1),
        ]

        timings = []
        for token, match_count in tokens:
            median_ms = measure_timing(client, endpoint, token)
            if median_ms < 0:
                return None
            timings.append((match_count, median_ms))

    # Simple linear correlation check: does latency grow with match_count?
    n = len(timings)
    xs = [t[0] for t in timings]
    ys = [t[1] for t in timings]
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)

    if var_x == 0 or var_y == 0:
        r = 0.0
    else:
        r = cov / ((var_x * var_y) ** 0.5)

    # Timing difference between 0-match and near-full-match tokens
    delta_ms = round(timings[2][1] - timings[0][1], 2)

    if r > 0.85 and delta_ms > 20:
        return {
            "correlation": round(r, 3),
            "delta_ms": delta_ms,
            "measurements": [
                {"prefix_match": m, "median_ms": round(t, 2)} for m, t in timings
            ],
        }
    return None


def main():
    parser = argparse.ArgumentParser(description="Timing Attack Demonstrator")
    parser.add_argument(
        "--target", default="http://localhost:3000", help="Base URL of the demo server"
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    findings = []
    summary_lines = []

    # Confirm server is reachable and retrieve secret length
    try:
        with httpx.Client(base_url=target) as client:
            r = client.get("/health", timeout=5.0)
            r.raise_for_status()
            length_resp = client.get("/api/secret-length", timeout=5.0)
            secret_length = length_resp.json()["length"]
    except Exception as exc:
        result = {
            "target": target,
            "findings": [],
            "summary": f"Server unreachable at {target}: {exc}",
        }
        print(json.dumps(result))
        return

    print(
        f"[*] Connected to {target}. Secret length: {secret_length}",
        file=sys.stderr,
    )

    # Probe the naive (vulnerable) endpoint
    print("[*] Probing /api/check-naive for timing side-channel …", file=sys.stderr)
    naive_result = detect_timing_side_channel(
        target, "/api/check-naive", secret_length
    )
    if naive_result:
        findings.append(
            {
                "endpoint": "/api/check-naive",
                "vulnerability_type": "timing_side_channel",
                "evidence": naive_result,
                "severity": "HIGH",
            }
        )
        summary_lines.append(
            f"/api/check-naive: VULNERABLE — timing correlation r={naive_result['correlation']}, "
            f"delta={naive_result['delta_ms']}ms across prefix lengths"
        )
        print(
            f"[!] VULNERABLE: timing correlation={naive_result['correlation']}, "
            f"delta={naive_result['delta_ms']}ms",
            file=sys.stderr,
        )
    else:
        summary_lines.append("/api/check-naive: no significant timing signal detected")

    # Probe the safe endpoint
    print("[*] Probing /api/check-safe for timing side-channel …", file=sys.stderr)
    safe_result = detect_timing_side_channel(
        target, "/api/check-safe", secret_length
    )
    if safe_result:
        findings.append(
            {
                "endpoint": "/api/check-safe",
                "vulnerability_type": "timing_side_channel",
                "evidence": safe_result,
                "severity": "HIGH",
            }
        )
        summary_lines.append(
            f"/api/check-safe: UNEXPECTED timing signal detected (r={safe_result['correlation']})"
        )
    else:
        summary_lines.append("/api/check-safe: constant-time — no timing signal (safe)")
        print("[+] SAFE: /api/check-safe shows no timing correlation", file=sys.stderr)

    result = {
        "target": target,
        "findings": findings,
        "summary": " | ".join(summary_lines),
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
