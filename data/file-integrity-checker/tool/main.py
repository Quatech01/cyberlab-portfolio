import argparse
import hashlib
import json
import sys

import httpx


def compute_hash(content_bytes: bytes) -> str:
    return hashlib.sha256(content_bytes).hexdigest()


def check_integrity(target: str) -> dict:
    findings = []
    total = 0

    try:
        with httpx.Client(base_url=target, timeout=10) as client:
            manifest_resp = client.get("/files")
            if manifest_resp.status_code != 200:
                print(
                    f"[ERROR] /files returned {manifest_resp.status_code}",
                    file=sys.stderr,
                )
                return {
                    "target": target,
                    "findings": [],
                    "summary": "Failed to retrieve file manifest from target.",
                }

            manifest = manifest_resp.json()
            total = len(manifest)
            print(
                f"[*] Manifest retrieved: {total} file(s) to verify",
                file=sys.stderr,
            )

            for entry in manifest:
                filename = entry["name"]
                baseline_hash = entry["baseline_hash"]

                file_resp = client.get(f"/file/{filename}")
                if file_resp.status_code != 200:
                    print(
                        f"[WARN] Cannot fetch '{filename}': HTTP {file_resp.status_code}",
                        file=sys.stderr,
                    )
                    continue

                file_data = file_resp.json()
                # Re-encode the received string to bytes before hashing, matching
                # how the server computed the baseline from its byte literals.
                current_content = file_data["content"].encode("utf-8", errors="replace")
                current_hash = compute_hash(current_content)

                if current_hash != baseline_hash:
                    findings.append(
                        {
                            "endpoint": f"/file/{filename}",
                            "vulnerability_type": "INTEGRITY_VIOLATION",
                            "evidence": (
                                f"File '{filename}' has been modified. "
                                f"Baseline SHA-256: {baseline_hash[:24]}..., "
                                f"Current SHA-256: {current_hash[:24]}..."
                            ),
                            "severity": "HIGH",
                        }
                    )
                    print(
                        f"[HIGH] INTEGRITY_VIOLATION detected in '{filename}'",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"[OK]   '{filename}' matches baseline hash",
                        file=sys.stderr,
                    )

    except httpx.ConnectError:
        print(f"[ERROR] Cannot connect to {target}", file=sys.stderr)
        return {
            "target": target,
            "findings": [],
            "summary": "Target unreachable — no files could be verified.",
        }
    except Exception as exc:
        print(f"[ERROR] Unexpected error: {exc}", file=sys.stderr)
        return {
            "target": target,
            "findings": [],
            "summary": f"Scan error: {exc}",
        }

    changed = len(findings)
    clean = total - changed
    if changed > 0:
        summary = (
            f"{changed} integrity violation(s) detected in {total} files checked "
            f"({clean} file(s) verified clean)."
        )
    else:
        summary = (
            f"All {total} files match their baseline hashes. "
            "No integrity violations detected."
        )

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker — detects unauthorized modifications via SHA-256 comparison"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target server (default: http://localhost:3000)",
    )
    args = parser.parse_args()

    print(f"[*] Starting file integrity check against {args.target}", file=sys.stderr)
    result = check_integrity(args.target)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
