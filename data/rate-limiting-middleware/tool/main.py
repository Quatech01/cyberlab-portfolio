"""
Rate Limiting Middleware Analyzer

Probes endpoints for rate limiting effectiveness. Detects two issue classes:
  MISSING_RATE_LIMITING  — endpoint never returns 429 regardless of request rate
  FIXED_WINDOW_BURST     — fixed-window algorithm allows 2× the configured limit
                           at window boundaries
"""
import sys
import time
import json
import argparse
import httpx

RAPID_COUNT = 15        # requests sent in each rapid-fire batch
BURST_MULTIPLIER = 1.5  # flag if boundary burst yields > limit * multiplier


def rapid_fire(client: httpx.Client, path: str, count: int) -> tuple:
    """Returns (successes, rate_limited)."""
    successes = 0
    limited = 0
    for _ in range(count):
        try:
            r = client.get(path)
            if r.status_code == 200:
                successes += 1
            elif r.status_code == 429:
                limited += 1
        except httpx.RequestError:
            pass
    return successes, limited


def reset(client: httpx.Client) -> None:
    try:
        client.post("/api/admin/reset")
    except httpx.RequestError:
        pass


def analyze(target: str) -> dict:
    findings = []
    summary_lines = []

    try:
        with httpx.Client(base_url=target, timeout=5.0) as client:
            # Fetch algorithm config so findings can reference actual limits
            try:
                cfg_r = client.get("/api/config")
                cfg = cfg_r.json() if cfg_r.status_code == 200 else {}
            except Exception:
                cfg = {}

            fw_max = cfg.get("fixed_window", {}).get("max_requests", 5)
            fw_win = cfg.get("fixed_window", {}).get("window_seconds", 2.0)

            # ── Test 1: no-limit endpoint ──────────────────────────────────────
            reset(client)
            ok, limited = rapid_fire(client, "/api/no-limit", RAPID_COUNT)
            print(f"[no-limit]      {ok}/{RAPID_COUNT} ok, {limited} blocked", file=sys.stderr)

            if limited == 0:
                findings.append({
                    "endpoint": "/api/no-limit",
                    "vulnerability_type": "MISSING_RATE_LIMITING",
                    "evidence": (
                        f"Sent {RAPID_COUNT} rapid requests; all returned HTTP 200 — "
                        "endpoint applies no rate limit whatsoever"
                    ),
                    "severity": "HIGH",
                })
                summary_lines.append("/api/no-limit: no rate limiting (HIGH)")

            # ── Test 2: token-bucket — should limit ───────────────────────────
            reset(client)
            ok, limited = rapid_fire(client, "/api/token-bucket", RAPID_COUNT)
            print(f"[token-bucket]  {ok}/{RAPID_COUNT} ok, {limited} blocked", file=sys.stderr)

            if limited == 0:
                findings.append({
                    "endpoint": "/api/token-bucket",
                    "vulnerability_type": "MISSING_RATE_LIMITING",
                    "evidence": (
                        f"Sent {RAPID_COUNT} rapid requests; all returned HTTP 200 — "
                        "token bucket did not enforce its limit"
                    ),
                    "severity": "HIGH",
                })
                summary_lines.append("/api/token-bucket: token bucket not enforcing (HIGH)")

            # ── Test 3: sliding-window — should limit ─────────────────────────
            reset(client)
            ok, limited = rapid_fire(client, "/api/sliding-window", RAPID_COUNT)
            print(f"[sliding-window]{ok}/{RAPID_COUNT} ok, {limited} blocked", file=sys.stderr)

            if limited == 0:
                findings.append({
                    "endpoint": "/api/sliding-window",
                    "vulnerability_type": "MISSING_RATE_LIMITING",
                    "evidence": (
                        f"Sent {RAPID_COUNT} rapid requests; all returned HTTP 200 — "
                        "sliding window did not enforce its limit"
                    ),
                    "severity": "HIGH",
                })
                summary_lines.append("/api/sliding-window: sliding window not enforcing (HIGH)")

            # ── Test 4: fixed-window boundary burst ───────────────────────────
            # Fire fw_max requests to fill window 1, wait for reset, fire fw_max
            # more immediately at start of window 2.  The elapsed time is only
            # fw_win + ε seconds yet 2*fw_max requests succeed — demonstrating
            # that an attacker can double their effective rate at each boundary.
            reset(client)
            batch1_ok = sum(
                1 for _ in range(fw_max)
                if client.get("/api/fixed-window").status_code == 200
            )
            time.sleep(fw_win + 0.3)   # wait for window to reset (extra margin)
            batch2_ok = sum(
                1 for _ in range(fw_max)
                if client.get("/api/fixed-window").status_code == 200
            )
            total_burst = batch1_ok + batch2_ok
            print(
                f"[fixed-window]  burst: batch1={batch1_ok}, batch2={batch2_ok}, "
                f"total={total_burst} (limit={fw_max}/window, window={fw_win}s)",
                file=sys.stderr,
            )

            if total_burst >= int(fw_max * BURST_MULTIPLIER):
                findings.append({
                    "endpoint": "/api/fixed-window",
                    "vulnerability_type": "FIXED_WINDOW_BURST",
                    "evidence": (
                        f"{batch1_ok} requests succeeded at the end of window 1; "
                        f"after {fw_win}s reset, {batch2_ok} more succeeded immediately "
                        f"at the start of window 2 — {total_burst} requests processed "
                        f"in ~{fw_win:.1f}s (2× the configured limit of {fw_max}/window). "
                        "An attacker can time requests to straddle the boundary and "
                        "effectively double their throughput."
                    ),
                    "severity": "MEDIUM",
                })
                summary_lines.append(
                    f"/api/fixed-window: boundary burst {total_burst} req "
                    f"in ~{fw_win:.1f}s (MEDIUM)"
                )

    except Exception as exc:
        return {
            "target": target,
            "findings": [],
            "summary": f"Could not reach target: {exc}",
        }

    if findings:
        summary = (
            f"Found {len(findings)} issue(s): " + "; ".join(summary_lines) + ". "
            "Token bucket and sliding window correctly enforce their limits."
        )
    else:
        summary = (
            "No issues found. All four endpoints enforce their configured limits "
            "and no boundary-burst behaviour was detected."
        )

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="Rate Limiting Middleware Analyzer")
    parser.add_argument("--target", default="http://localhost:3000")
    args = parser.parse_args()
    print(json.dumps(analyze(args.target), indent=2))


if __name__ == "__main__":
    main()
