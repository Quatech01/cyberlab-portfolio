"""SOC Tier 1 Pre-Triage Tool

Fetches open alerts from the simulator, deduplicates by source IP + rule,
scores false-positive likelihood, and recommends escalation actions.
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    print(json.dumps({"error": "httpx not installed"}))
    sys.exit(1)


ESCALATION_CATEGORIES = {"lateral_movement", "privilege_escalation", "malware_beacon"}
CRITICAL_SEVERITIES = {"critical", "high"}

# Rules whose repeated firing from the same IP is likely a false positive
FP_PRONE_RULES = {"SSH Brute Force Detected", "RDP Password Spray", "Horizontal Port Scan"}


def fetch_alerts(target: str) -> list[dict]:
    try:
        r = httpx.get(f"{target}/api/alerts", timeout=10, params={"status": "open"})
        r.raise_for_status()
        return r.json()
    except Exception:
        return []


def deduplicate(alerts: list[dict]) -> list[dict]:
    """Keep only the most recent alert per (source_ip, rule_name) pair."""
    seen: dict[tuple, dict] = {}
    for alert in alerts:
        key = (alert.get("source", {}).get("ip", ""), alert.get("rule", {}).get("name", ""))
        ts = alert.get("@timestamp", "")
        if key not in seen or ts > seen[key].get("@timestamp", ""):
            seen[key] = alert
    return list(seen.values())


def score_false_positive(alert: dict, ip_counts: dict[str, int]) -> float:
    """Return a 0.0–1.0 likelihood that the alert is a false positive."""
    score = 0.0
    rule = alert.get("rule", {}).get("name", "")
    source_ip = alert.get("source", {}).get("ip", "")

    # High-frequency IP firing the same rule repeatedly → likely scanner noise
    if ip_counts.get(source_ip, 0) >= 3:
        score += 0.4

    # FP-prone rule names
    if rule in FP_PRONE_RULES:
        score += 0.3

    # Low severity reduces urgency
    sev = alert.get("kibana.alert.severity", "")
    if sev == "low":
        score += 0.2
    elif sev == "medium":
        score += 0.1

    return min(score, 1.0)


def recommend_action(alert: dict, fp_score: float) -> str:
    cat = alert.get("event", {}).get("category", "")
    sev = alert.get("kibana.alert.severity", "")

    if fp_score >= 0.6:
        return "close_fp"
    if cat in ESCALATION_CATEGORIES and sev in CRITICAL_SEVERITIES:
        return "escalate"
    return "investigate"


def run_triage(target: str) -> dict:
    raw_alerts = fetch_alerts(target)

    if not raw_alerts:
        return {
            "target": target,
            "findings": [],
            "summary": {
                "total_open": 0,
                "after_dedup": 0,
                "recommended_escalate": 0,
                "recommended_investigate": 0,
                "recommended_close_fp": 0,
            },
        }

    # Count how many open alerts exist per source IP
    ip_counts: dict[str, int] = defaultdict(int)
    for a in raw_alerts:
        ip = a.get("source", {}).get("ip", "")
        if ip:
            ip_counts[ip] += 1

    deduped = deduplicate(raw_alerts)

    findings = []
    for alert in deduped:
        fp_score = score_false_positive(alert, ip_counts)
        action = recommend_action(alert, fp_score)
        findings.append(
            {
                "endpoint": "/api/alerts",
                "vulnerability_type": alert.get("event", {}).get("category", "unknown"),
                "evidence": {
                    "alert_id": alert["event"]["id"],
                    "rule": alert.get("rule", {}).get("name", ""),
                    "host": alert.get("host", {}).get("name", ""),
                    "source_ip": alert.get("source", {}).get("ip", ""),
                    "severity": alert.get("kibana.alert.severity", ""),
                    "timestamp": alert.get("@timestamp", ""),
                    "fp_score": round(fp_score, 2),
                },
                "severity": alert.get("kibana.alert.severity", "low").upper(),
                "recommended_action": action,
            }
        )

    escalate_count = sum(1 for f in findings if f["recommended_action"] == "escalate")
    investigate_count = sum(1 for f in findings if f["recommended_action"] == "investigate")
    close_fp_count = sum(1 for f in findings if f["recommended_action"] == "close_fp")

    return {
        "target": target,
        "findings": findings,
        "summary": {
            "total_open": len(raw_alerts),
            "after_dedup": len(deduped),
            "recommended_escalate": escalate_count,
            "recommended_investigate": investigate_count,
            "recommended_close_fp": close_fp_count,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="SOC Tier 1 Pre-Triage Tool")
    parser.add_argument("--target", default="http://localhost:3000", help="Base URL of the simulator")
    args = parser.parse_args()

    result = run_triage(args.target)
    print(json.dumps(result, indent=2))

    total = result["summary"]["total_open"]
    escalate = result["summary"]["recommended_escalate"]
    print(f"\n[SOC Triage] {total} open alerts → {escalate} recommended for escalation", file=sys.stderr)


if __name__ == "__main__":
    main()
