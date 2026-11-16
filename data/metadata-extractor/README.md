# Metadata Extractor

A cybersecurity scanner that retrieves files from a target server and analyses their embedded metadata for sensitive information leakage — GPS coordinates, email addresses, software version strings, and confidential classification labels.

## What This Demonstrates

Modern file formats embed a surprising amount of hidden data. A JPEG photograph can carry the photographer's GPS coordinates, email address, camera model, and the exact version of the editing software used. A Word document exported to PDF can retain the author's internal email, the name of the corporate template, and subject lines marked "CONFIDENTIAL INTERNAL USE ONLY" — all readable by anyone who downloads the file.

This project demonstrates:

- **GPS location disclosure** — EXIF latitude/longitude fields reveal where a photo was taken, potentially exposing a home address or sensitive location.
- **Email address disclosure** — EXIF Artist/Copyright fields and PDF Author metadata often contain internal email addresses, leaking organisational identity.
- **Software version disclosure** — Knowing the exact version of Photoshop, Word, or Acrobat used to create a file helps an attacker identify known CVEs in that software.
- **Sensitive classification labels** — Document subject and keyword fields frequently contain "CONFIDENTIAL", "INTERNAL", or "RESTRICTED" markers that signal high-value targets.

## How It Works

```
demo server (FastAPI)         tool/main.py          tests/test.py
─────────────────────         ────────────          ─────────────
GET /files          ◄──────── list files  ◄──────── run tool via subprocess
GET /files/vuln_photo.jpg ◄── download   ──────────► assert GPS finding
GET /files/safe_photo.jpg ◄── download   ──────────► assert no findings
GET /files/vuln_document.pdf ◄ download  ──────────► assert CONFIDENTIAL label
GET /files/safe_document.pdf ◄ download  ──────────► assert no findings
```

**Demo server** generates four synthetic files in-memory at startup:
- `vuln_photo.jpg` — JPEG with GPS coordinates (51°N London area), author email, camera make/model, and software version in EXIF
- `safe_photo.jpg` — JPEG with no EXIF metadata
- `vuln_document.pdf` — PDF with author email, MS Word version string, and "CONFIDENTIAL INTERNAL USE ONLY" in the subject
- `safe_document.pdf` — PDF with no metadata

**Scanner tool** downloads each file, extracts EXIF (via `piexif`) or PDF properties (via `pypdf`), applies severity rules, and outputs a JSON report.

**Tests** (29 pytest cases) verify true positives, false positives, output format, and graceful error handling.

## Quick Start

```bash
# Install dependencies
pip install -r server/requirements.txt
pip install -r tool/requirements.txt
pip install -r tests/requirements.txt

# Run the demo server
cd server
python main.py
# Server listening on http://127.0.0.1:3000

# In a separate terminal — run the scanner
cd tool
python main.py --target http://localhost:3000

# Run the full test suite
cd tests
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/files/vuln_photo.jpg",
      "vulnerability_type": "GPS Location Disclosure",
      "evidence": "GPS embedded in image EXIF: 51.507222°N, 0.127778°W",
      "severity": "HIGH"
    },
    {
      "endpoint": "/files/vuln_photo.jpg",
      "vulnerability_type": "Email Address Disclosure",
      "evidence": "EXIF artist: j.smith@contoso-internal.com",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/files/vuln_photo.jpg",
      "vulnerability_type": "Software Version Disclosure",
      "evidence": "EXIF software: Adobe Photoshop CS6 13.0.1",
      "severity": "LOW"
    },
    {
      "endpoint": "/files/vuln_document.pdf",
      "vulnerability_type": "Sensitive Classification Label",
      "evidence": "PDF Subject: Q4 Financial Summary - CONFIDENTIAL INTERNAL USE ONLY",
      "severity": "HIGH"
    },
    {
      "endpoint": "/files/vuln_document.pdf",
      "vulnerability_type": "Email Address Disclosure",
      "evidence": "PDF Author: j.davies@contoso-internal.com",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Found 7 metadata finding(s) across 2 file(s). Severity breakdown: HIGH=2, MEDIUM=2, LOW=3."
}
```

## Key Takeaways

- **Strip EXIF before publishing photos.** Tools like `exiftool -all= photo.jpg` or ImageMagick's `mogrify -strip` remove all metadata before upload.
- **Review PDF metadata before sharing documents.** In Word: File → Info → Check for Issues → Inspect Document → Remove Document Properties and Personal Information.
- **Never put classification labels in metadata fields.** Subject and keyword fields are plaintext and are not access-controlled.
- **Software version strings aid reconnaissance.** Knowing an organisation uses Word 2016 (pre-patch) or Photoshop CS6 narrows the attack surface for known exploits.

## Further Reading

- [OWASP Information Exposure Through Metadata](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [Exif Standard — JEITA CP-3451C](https://www.cipa.jp/std/documents/e/DC-X008-Translation-2019-E.pdf)
- [PDF Reference — Document Information Dictionary (Adobe)](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf) (Section 14.3.3)
