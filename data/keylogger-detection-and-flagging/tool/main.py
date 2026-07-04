"""Keylogger Detection and Flagging Tool.

Queries four system-scan API endpoints (processes, registry, files, network
connections) and cross-references results against a rule set of known keylogger
indicators. Emits a structured JSON threat report to stdout; human-readable
progress goes to stderr.

Usage:
    python main.py --target http://localhost:3000
"""
import argparse
import json
import sys

import httpx

# ── Detection rule sets ────────────────────────────────────────────────────────

KNOWN_KEYLOGGER_PROCESSES = {
    "hook32.dll",
    "ardamax.exe",
    "kgb_keylogger.exe",
    "keylogger.exe",
    "kl.exe",
    "perfect_keylogger.exe",
    "revealer_keylogger.exe",
    "elite_keylogger.exe",
    "refog_keylogger.exe",
    "spyrix.exe",
}

PROCESS_PATTERNS = ["keylog", "keystroke", "hookkey", "keycap", "kl_"]

REGISTRY_NAME_PATTERNS = ["kl_", "keylog", "keystroke", "keycap", "keyboard"]
SUSPICIOUS_EXEC_LOCATIONS = [
    "\\temp\\", "\\tmp\\", "c:\\users\\public\\", "c:\\temp\\", "/tmp/",
]

FILE_PATTERNS = ["kl_", "keylog", "keystroke", "keycap"]

KNOWN_GOOD_IP_PREFIXES = [
    "142.250.", "13.107.", "52.96.", "52.84.", "8.8.", "1.1.1.", "23.23.",
]
STANDARD_PORTS = {80, 443, 8080, 8443, 53}


# ── Per-category scanners ──────────────────────────────────────────────────────

def check_processes(target: str, client: httpx.Client) -> list:
    findings = []
    try:
        resp = client.get(f"{target}/scan/processes", timeout=5)
        resp.raise_for_status()
        processes = resp.json().get("results", [])
    except Exception:
        return findings

    for proc in processes:
        name = proc.get("name", "").lower()
        pid = proc.get("pid", "?")
        if name in {p.lower() for p in KNOWN_KEYLOGGER_PROCESSES}:
            findings.append({
                "endpoint": "/scan/processes",
                "vulnerability_type": "known_keylogger_process",
                "evidence": (
                    f"Process '{proc['name']}' (PID {pid}) matches a known"
                    " keylogger signature"
                ),
                "severity": "HIGH",
            })
        elif any(pattern in name for pattern in PROCESS_PATTERNS):
            findings.append({
                "endpoint": "/scan/processes",
                "vulnerability_type": "suspicious_process_name",
                "evidence": (
                    f"Process '{proc['name']}' (PID {pid}) contains a"
                    " keyboard-capture naming pattern"
                ),
                "severity": "MEDIUM",
            })
    return findings


def check_registry(target: str, client: httpx.Client) -> list:
    findings = []
    try:
        resp = client.get(f"{target}/scan/registry", timeout=5)
        resp.raise_for_status()
        entries = resp.json().get("results", [])
    except Exception:
        return findings

    for entry in entries:
        key = entry.get("key", "")
        value = entry.get("value", "").lower()
        data = entry.get("data", "").lower()
        is_autorun = "currentversion\\run" in key.lower()

        name_suspicious = any(p in value for p in REGISTRY_NAME_PATTERNS)
        path_suspicious = any(loc in data for loc in SUSPICIOUS_EXEC_LOCATIONS)

        if is_autorun and name_suspicious:
            findings.append({
                "endpoint": "/scan/registry",
                "vulnerability_type": "keylogger_autorun_registry",
                "evidence": (
                    f"Autorun key '{key}' value '{entry['value']}' →"
                    f" '{entry['data']}' contains a keyboard-capture naming pattern"
                ),
                "severity": "HIGH",
            })
        elif is_autorun and path_suspicious:
            findings.append({
                "endpoint": "/scan/registry",
                "vulnerability_type": "suspicious_autorun_location",
                "evidence": (
                    f"Autorun key '{key}' → '{entry['data']}' launches an"
                    " executable from a suspicious temporary directory"
                ),
                "severity": "MEDIUM",
            })
    return findings


def check_files(target: str, client: httpx.Client) -> list:
    findings = []
    try:
        resp = client.get(f"{target}/scan/files", timeout=5)
        resp.raise_for_status()
        files = resp.json().get("results", [])
    except Exception:
        return findings

    for f in files:
        path = f.get("path", "")
        filename = path.replace("/", "\\").split("\\")[-1].lower()
        if any(pattern in filename for pattern in FILE_PATTERNS):
            findings.append({
                "endpoint": "/scan/files",
                "vulnerability_type": "keylogger_artefact_file",
                "evidence": (
                    f"File '{path}' has a keyboard-capture naming pattern"
                    " indicative of a keystroke log or capture dump"
                ),
                "severity": "MEDIUM",
            })
    return findings


def check_connections(target: str, client: httpx.Client) -> list:
    findings = []
    try:
        resp = client.get(f"{target}/scan/connections", timeout=5)
        resp.raise_for_status()
        conns = resp.json().get("results", [])
    except Exception:
        return findings

    for conn in conns:
        remote_ip = conn.get("remote_address", "")
        remote_port = conn.get("remote_port", 0)
        known_good = any(remote_ip.startswith(p) for p in KNOWN_GOOD_IP_PREFIXES)

        if not known_good and remote_port not in STANDARD_PORTS:
            findings.append({
                "endpoint": "/scan/connections",
                "vulnerability_type": "suspicious_c2_connection",
                "evidence": (
                    f"Outbound connection to {remote_ip}:{remote_port} —"
                    " unknown destination on a non-standard port (possible C2 channel)"
                ),
                "severity": "HIGH",
            })
        elif not known_good:
            findings.append({
                "endpoint": "/scan/connections",
                "vulnerability_type": "unknown_outbound_connection",
                "evidence": (
                    f"Outbound connection to {remote_ip}:{remote_port} —"
                    " IP does not match any recognised cloud-provider range"
                ),
                "severity": "MEDIUM",
            })
    return findings


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Keylogger Detection and Flagging Tool"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the demo server (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    findings: list = []

    try:
        with httpx.Client() as client:
            try:
                client.get(f"{target}/health", timeout=5)
            except Exception:
                result = {
                    "target": target,
                    "findings": [],
                    "summary": "Server unreachable — no scan performed",
                }
                print(json.dumps(result, indent=2))
                return

            findings.extend(check_processes(target, client))
            findings.extend(check_registry(target, client))
            findings.extend(check_files(target, client))
            findings.extend(check_connections(target, client))

    except Exception as exc:
        print(f"[scanner] Fatal error: {exc}", file=sys.stderr)
        result = {
            "target": target,
            "findings": [],
            "summary": f"Scan aborted: {exc}",
        }
        print(json.dumps(result, indent=2))
        return

    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")

    if findings:
        print(
            f"[scanner] {len(findings)} indicator(s) found:"
            f" {high} HIGH, {medium} MEDIUM, {low} LOW",
            file=sys.stderr,
        )
    else:
        print("[scanner] No keylogger indicators detected", file=sys.stderr)

    result = {
        "target": target,
        "findings": findings,
        "summary": (
            f"{len(findings)} keylogger indicator(s) detected"
            f" ({high} HIGH, {medium} MEDIUM, {low} LOW)"
            if findings
            else "No keylogger indicators detected"
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
