#!/usr/bin/env python3
"""
Hex Dump Viewer with Pattern Highlighting

Fetches binary files from a target server, renders hex dumps, and flags:
  - Suspicious embedded strings (XSS scripts, shell commands, downloaders)
  - High Shannon entropy regions that may indicate encrypted or packed content

Usage:
    python main.py --target http://localhost:3000
"""
import argparse
import json
import math
import sys
from typing import Any

import httpx

# ── Known file-type signatures (magic bytes at offset 0) ────────────────────

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b'\x89PNG\r\n\x1a\n', "PNG image"),
    (b'\xff\xd8\xff',       "JPEG image"),
    (b'%PDF',              "PDF document"),
    (b'PK\x03\x04',        "ZIP archive"),
    (b'\x7fELF',           "ELF executable"),
    (b'MZ',                "Windows PE executable"),
    (b'GIF87a',            "GIF87 image"),
    (b'GIF89a',            "GIF89 image"),
    (b'\x1f\x8b',          "GZIP archive"),
    (b'\xca\xfe\xba\xbe',  "Java class file"),
    (b'\xfe\xed\xfa\xce',  "Mach-O 32-bit"),
    (b'\xfe\xed\xfa\xcf',  "Mach-O 64-bit"),
]

# ── Suspicious byte patterns ─────────────────────────────────────────────────
# (pattern, vulnerability_type, severity)

SUSPICIOUS_PATTERNS: list[tuple[bytes, str, str]] = [
    (b'<script',    "embedded_script",   "HIGH"),
    (b'<iframe',    "embedded_iframe",   "HIGH"),
    (b'/bin/bash',  "shell_command",     "HIGH"),
    (b'/bin/sh ',   "shell_command",     "HIGH"),
    (b'cmd.exe',    "shell_command",     "HIGH"),
    (b'powershell', "shell_command",     "HIGH"),
    (b'eval(',      "code_execution",    "HIGH"),
    (b'exec(',      "code_execution",    "HIGH"),
    (b'/dev/tcp/',  "shell_command",     "HIGH"),
    (b'wget ',      "download_command",  "MEDIUM"),
    (b'curl ',      "download_command",  "MEDIUM"),
]

ENTROPY_THRESHOLD = 7.5


# ── Analysis helpers ─────────────────────────────────────────────────────────


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


def identify_file_type(data: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES:
        if data[: len(magic)] == magic:
            return label
    return "Unknown binary"


def hex_dump_lines(data: bytes, max_lines: int = 4) -> list[str]:
    lines = []
    limit = min(len(data), max_lines * 16)
    for i in range(0, limit, 16):
        chunk = data[i : i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}: {hex_str:<47}  {ascii_str}")
    if len(data) > limit:
        lines.append(f"  ... ({len(data) - limit} more bytes not shown)")
    return lines


def scan_file(name: str, data: bytes, endpoint: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    data_lower = data.lower()

    # Suspicious string scan — report first match only to avoid duplication
    for pattern, vuln_type, severity in SUSPICIOUS_PATTERNS:
        idx = data_lower.find(pattern.lower())
        if idx != -1:
            decoded = pattern.decode("latin-1")
            findings.append(
                {
                    "endpoint": endpoint,
                    "vulnerability_type": vuln_type,
                    "evidence": f"Found '{decoded}' at offset 0x{idx:04x} in {name}",
                    "severity": severity,
                }
            )
            break

    # Entropy check (independent of string scan)
    entropy = shannon_entropy(data)
    if entropy >= ENTROPY_THRESHOLD:
        findings.append(
            {
                "endpoint": endpoint,
                "vulnerability_type": "high_entropy",
                "evidence": (
                    f"Shannon entropy {entropy:.2f} >= {ENTROPY_THRESHOLD} in {name} "
                    "(possible encryption or packing)"
                ),
                "severity": "MEDIUM",
            }
        )

    return findings


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Hex Dump Viewer with Pattern Highlighting")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the demo server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    target = args.target.rstrip("/")
    all_findings: list[dict[str, Any]] = []
    file_count = 0

    print(f"[*] Target: {target}", file=sys.stderr)

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{target}/files")
            resp.raise_for_status()
            file_list: list[dict] = resp.json()
            file_count = len(file_list)

            print(f"[*] Found {file_count} file(s) to analyse", file=sys.stderr)

            for info in file_list:
                name = info["name"]
                endpoint = f"/files/{name}"

                resp = client.get(f"{target}{endpoint}")
                resp.raise_for_status()
                data = resp.content

                entropy = shannon_entropy(data)
                file_type = identify_file_type(data)
                findings = scan_file(name, data, endpoint)
                all_findings.extend(findings)

                marker = "[!]" if findings else "[+]"
                status = "SUSPICIOUS" if findings else "CLEAN"
                print(
                    f"{marker} {name} | {file_type} | entropy={entropy:.2f} | {status}",
                    file=sys.stderr,
                )
                for line in hex_dump_lines(data, max_lines=2):
                    print(line, file=sys.stderr)
                for f in findings:
                    print(
                        f"    >> [{f['severity']}] {f['vulnerability_type']}: {f['evidence']}",
                        file=sys.stderr,
                    )

    except (httpx.ConnectError, httpx.ConnectTimeout):
        print(f"[-] Cannot connect to {target}", file=sys.stderr)
        result = {
            "target": target,
            "findings": [],
            "summary": f"Error: cannot connect to {target}",
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    except Exception as exc:
        print(f"[-] Unexpected error: {exc}", file=sys.stderr)
        result = {
            "target": target,
            "findings": [],
            "summary": f"Error: {exc}",
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    flagged = len({f["endpoint"] for f in all_findings})
    result = {
        "target": target,
        "findings": all_findings,
        "summary": (
            f"Analysed {file_count} file(s). "
            f"Found {len(all_findings)} suspicious pattern(s) across {flagged} file(s)."
        ),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
