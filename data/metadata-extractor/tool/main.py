"""Metadata Extractor — scans a file-hosting server for sensitive metadata leakage.

Fetches every file from the target's /files endpoint, extracts EXIF (JPEG) or
document properties (PDF), and reports findings that could aid an attacker:
GPS coordinates, embedded email addresses, software version strings, and
sensitive classification labels in document subject/keyword fields.
"""

import argparse
import io
import json
import sys

import httpx
import piexif
from pypdf import PdfReader


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _rational(r):
    """Convert a piexif rational tuple (num, den) to float."""
    if isinstance(r, (list, tuple)) and len(r) == 2:
        num, den = r
        return float(num) / float(den) if den else 0.0
    return float(r)


def _gps_to_decimal(dms_tuple, ref: str) -> float:
    degrees = _rational(dms_tuple[0])
    minutes = _rational(dms_tuple[1])
    seconds = _rational(dms_tuple[2])
    dd = degrees + minutes / 60.0 + seconds / 3600.0
    if ref.upper() in ("S", "W"):
        dd = -dd
    return round(dd, 6)


def extract_jpeg_metadata(data: bytes) -> dict:
    """Return a flat dict of interesting EXIF fields, or {} on error."""
    try:
        exif = piexif.load(data)
    except Exception:
        return {}

    result: dict = {}

    ifd0 = exif.get("0th", {})
    _str_fields = {
        piexif.ImageIFD.Make: "camera_make",
        piexif.ImageIFD.Model: "camera_model",
        piexif.ImageIFD.Software: "software",
        piexif.ImageIFD.Artist: "artist",
        piexif.ImageIFD.Copyright: "copyright",
        piexif.ImageIFD.DateTime: "datetime",
    }
    for tag_id, key in _str_fields.items():
        raw = ifd0.get(tag_id)
        if raw:
            result[key] = raw.decode("utf-8", errors="replace").rstrip("\x00")

    gps = exif.get("GPS", {})
    lat_tuple = gps.get(piexif.GPSIFD.GPSLatitude)
    lat_ref = (gps.get(piexif.GPSIFD.GPSLatitudeRef) or b"").decode()
    lon_tuple = gps.get(piexif.GPSIFD.GPSLongitude)
    lon_ref = (gps.get(piexif.GPSIFD.GPSLongitudeRef) or b"").decode()

    if lat_tuple and lon_tuple:
        result["gps_latitude"] = _gps_to_decimal(lat_tuple, lat_ref)
        result["gps_longitude"] = _gps_to_decimal(lon_tuple, lon_ref)
        result["gps_lat_ref"] = lat_ref
        result["gps_lon_ref"] = lon_ref

    return result


def extract_pdf_metadata(data: bytes) -> dict:
    """Return a flat dict of PDF document properties, or {} on error."""
    try:
        reader = PdfReader(io.BytesIO(data))
        meta = reader.metadata
        if not meta:
            return {}
        return {k.lstrip("/"): str(v) for k, v in meta.items() if v}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

_SENSITIVE_KEYWORDS = ("confidential", "internal", "secret", "private", "restricted")


def _contains_email(value: str) -> bool:
    return "@" in value and "." in value.split("@")[-1]


def _contains_sensitive_label(value: str) -> bool:
    lower = value.lower()
    return any(kw in lower for kw in _SENSITIVE_KEYWORDS)


def analyze(endpoint: str, metadata: dict, file_type: str) -> list[dict]:
    """Return a list of findings for this file's metadata."""
    findings: list[dict] = []

    if file_type == "jpeg":
        # GPS coordinates — highest severity
        if "gps_latitude" in metadata and "gps_longitude" in metadata:
            lat = metadata["gps_latitude"]
            lon = metadata["gps_longitude"]
            lat_ref = metadata.get("gps_lat_ref", "")
            lon_ref = metadata.get("gps_lon_ref", "")
            findings.append(
                {
                    "endpoint": endpoint,
                    "vulnerability_type": "GPS Location Disclosure",
                    "evidence": (
                        f"GPS embedded in image EXIF: "
                        f"{abs(lat):.6f}°{lat_ref}, {abs(lon):.6f}°{lon_ref}"
                    ),
                    "severity": "HIGH",
                }
            )

        # Email in artist or copyright
        for field in ("artist", "copyright"):
            value = metadata.get(field, "")
            if value and _contains_email(value):
                findings.append(
                    {
                        "endpoint": endpoint,
                        "vulnerability_type": "Email Address Disclosure",
                        "evidence": f"EXIF {field}: {value}",
                        "severity": "MEDIUM",
                    }
                )

        # Software version
        for field in ("software", "camera_make", "camera_model"):
            value = metadata.get(field, "")
            if value:
                findings.append(
                    {
                        "endpoint": endpoint,
                        "vulnerability_type": "Software Version Disclosure",
                        "evidence": f"EXIF {field}: {value}",
                        "severity": "LOW",
                    }
                )

    elif file_type == "pdf":
        # Email in author field
        for field in ("Author", "Creator", "Producer"):
            value = metadata.get(field, "")
            if value and _contains_email(value):
                findings.append(
                    {
                        "endpoint": endpoint,
                        "vulnerability_type": "Email Address Disclosure",
                        "evidence": f"PDF {field}: {value}",
                        "severity": "MEDIUM",
                    }
                )

        # Sensitive classification labels
        for field in ("Subject", "Keywords"):
            value = metadata.get(field, "")
            if value and _contains_sensitive_label(value):
                findings.append(
                    {
                        "endpoint": endpoint,
                        "vulnerability_type": "Sensitive Classification Label",
                        "evidence": f"PDF {field}: {value}",
                        "severity": "HIGH",
                    }
                )

        # Software / creator tool — only flag when a version number is present
        for field in ("Creator", "Producer"):
            value = metadata.get(field, "")
            if value and not _contains_email(value) and any(ch.isdigit() for ch in value):
                findings.append(
                    {
                        "endpoint": endpoint,
                        "vulnerability_type": "Software Version Disclosure",
                        "evidence": f"PDF {field}: {value}",
                        "severity": "LOW",
                    }
                )

    return findings


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan(target: str) -> dict:
    target = target.rstrip("/")
    all_findings: list[dict] = []

    try:
        with httpx.Client(timeout=10) as client:
            files_resp = client.get(f"{target}/files")
            files_resp.raise_for_status()
            filenames: list[str] = files_resp.json().get("files", [])

            for filename in filenames:
                endpoint = f"/files/{filename}"
                try:
                    file_resp = client.get(f"{target}{endpoint}")
                    file_resp.raise_for_status()
                    data = file_resp.content

                    if filename.lower().endswith((".jpg", ".jpeg")):
                        metadata = extract_jpeg_metadata(data)
                        findings = analyze(endpoint, metadata, "jpeg")
                    elif filename.lower().endswith(".pdf"):
                        metadata = extract_pdf_metadata(data)
                        findings = analyze(endpoint, metadata, "pdf")
                    else:
                        findings = []

                    all_findings.extend(findings)
                except Exception as exc:
                    print(f"[warn] could not scan {endpoint}: {exc}", file=sys.stderr)

    except Exception as exc:
        print(f"[error] could not reach {target}: {exc}", file=sys.stderr)
        return {"target": target, "findings": [], "summary": "Server unreachable"}

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")
    affected = len({f["endpoint"] for f in all_findings})

    summary = (
        f"Found {len(all_findings)} metadata finding(s) across {affected} file(s). "
        f"Severity breakdown: HIGH={high}, MEDIUM={medium}, LOW={low}."
    )

    return {"target": target, "findings": all_findings, "summary": summary}


def main() -> None:
    parser = argparse.ArgumentParser(description="Metadata leakage scanner")
    parser.add_argument("--target", default="http://localhost:3000", help="Base URL of the target server")
    args = parser.parse_args()

    result = scan(args.target)
    print(json.dumps(result, indent=2))

    affected_files = {f["endpoint"] for f in result["findings"]}
    for finding in result["findings"]:
        sev = finding["severity"]
        marker = "!!" if sev == "HIGH" else ("! " if sev == "MEDIUM" else "  ")
        print(f"  [{sev}] {marker} {finding['endpoint']}: {finding['vulnerability_type']}", file=sys.stderr)
    print(f"\n{result['summary']}", file=sys.stderr)


if __name__ == "__main__":
    main()
