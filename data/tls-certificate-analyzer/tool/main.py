"""TLS Certificate Analyzer — fetches X.509 PEM certificates from a demo server and flags security issues."""

import argparse
import datetime
import json
import sys

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _analyze_cert(cert_id: str, pem_data: str, base_url: str) -> list[dict]:
    findings = []
    endpoint = f"{base_url}/certificates/{cert_id}"

    try:
        cert = x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as exc:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "INVALID_CERTIFICATE",
            "evidence": f"Failed to parse PEM data: {exc}",
            "severity": "HIGH",
        })
        return findings

    now = datetime.datetime.utcnow()

    # Expiry
    if cert.not_valid_after_utc.replace(tzinfo=None) < now:
        delta = now - cert.not_valid_after_utc.replace(tzinfo=None)
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "EXPIRED_CERTIFICATE",
            "evidence": (
                f"Certificate expired {delta.days} day(s) ago "
                f"on {cert.not_valid_after_utc.date().isoformat()}"
            ),
            "severity": "HIGH",
        })
    elif cert.not_valid_after_utc.replace(tzinfo=None) < now + datetime.timedelta(days=30):
        delta = cert.not_valid_after_utc.replace(tzinfo=None) - now
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "EXPIRING_SOON",
            "evidence": (
                f"Certificate expires in {delta.days} day(s) "
                f"on {cert.not_valid_after_utc.date().isoformat()}"
            ),
            "severity": "MEDIUM",
        })

    # Self-signed (issuer DN == subject DN)
    if cert.issuer == cert.subject:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "SELF_SIGNED_CERTIFICATE",
            "evidence": (
                f"Issuer and subject are identical: {cert.subject.rfc4514_string()!r}. "
                "Browsers and clients reject self-signed certificates as untrusted."
            ),
            "severity": "MEDIUM",
        })

    # Weak RSA key
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        if key_size < 2048:
            findings.append({
                "endpoint": endpoint,
                "vulnerability_type": "WEAK_RSA_KEY",
                "evidence": (
                    f"RSA key is {key_size} bits. "
                    "The minimum recommended size is 2048 bits (NIST SP 800-131A, 2015)."
                ),
                "severity": "HIGH",
            })
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size = pub_key.key_size
        if key_size < 256:
            findings.append({
                "endpoint": endpoint,
                "vulnerability_type": "WEAK_EC_KEY",
                "evidence": (
                    f"Elliptic curve key is {key_size} bits. "
                    "The minimum recommended curve is P-256 (256 bits)."
                ),
                "severity": "HIGH",
            })

    # Missing Subject Alternative Names
    try:
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "MISSING_SUBJECT_ALTERNATIVE_NAME",
            "evidence": (
                "Certificate has no Subject Alternative Names (SAN) extension. "
                "RFC 2818 §3.1 requires SANs; CN-only matching was deprecated in Chrome 58 (2017)."
            ),
            "severity": "MEDIUM",
        })

    return findings


def scan(target: str) -> dict:
    try:
        client = httpx.Client(timeout=10.0)
        response = client.get(f"{target}/certificates")
        response.raise_for_status()
        cert_list = response.json().get("certificates", [])
    except Exception as exc:
        print(f"[ERROR] Cannot reach {target}: {exc}", file=sys.stderr)
        return {
            "target": target,
            "findings": [],
            "summary": f"Scan aborted — target unreachable: {exc}",
        }

    print(f"[INFO] Analyzing {len(cert_list)} certificate(s) from {target}", file=sys.stderr)

    all_findings: list[dict] = []
    for item in cert_list:
        cert_id = item["id"]
        print(f"[INFO]   {cert_id}: {item['label']}", file=sys.stderr)
        try:
            r = client.get(f"{target}/certificates/{cert_id}")
            r.raise_for_status()
            pem = r.json().get("pem", "")
            all_findings.extend(_analyze_cert(cert_id, pem, target))
        except Exception as exc:
            print(f"[WARN]   Failed to fetch {cert_id}: {exc}", file=sys.stderr)

    client.close()

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    parts = []
    if high:
        parts.append(f"{high} HIGH")
    if medium:
        parts.append(f"{medium} MEDIUM")
    if low:
        parts.append(f"{low} LOW")

    summary = (
        f"Analyzed {len(cert_list)} certificate(s). "
        + (f"Found {len(all_findings)} issue(s): {', '.join(parts)}." if all_findings else "No issues found.")
    )
    print(f"[INFO] {summary}", file=sys.stderr)

    return {"target": target, "findings": all_findings, "summary": summary}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Certificate Analyzer")
    parser.add_argument(
        "--target", default="http://localhost:3000",
        help="Base URL of the demo server (default: http://localhost:3000)"
    )
    args = parser.parse_args()
    print(json.dumps(scan(args.target), indent=2))
