# Hex Dump Viewer with Pattern Highlighting

A binary file analysis tool that fetches files from a server, renders hex dumps, and automatically highlights suspicious patterns: embedded scripts, shell commands, and high-entropy regions that may indicate encrypted or packed content.

## What This Demonstrates

When triaging potentially malicious binaries or forensic artefacts, raw hex dumps alone leave too much to the eye. This project shows three automated detection techniques used in real malware analysis workflows:

- **Magic byte identification** — file type is determined by the first few bytes (the "magic" or file signature), not by the extension. A JPEG renamed to `.exe` is still a JPEG; an ELF with a `.txt` extension is still an ELF.
- **Suspicious string scanning** — attackers embed XSS payloads, reverse-shell stagers, and download commands inside binaries. Byte-level string matching surfaces these regardless of file type.
- **Shannon entropy analysis** — encrypted, packed, or compressed data has high entropy (close to 8 bits/byte for random data). Files with entropy ≥ 7.5 are flagged as possibly obfuscated — a common indicator in real-world malware.

## How It Works

```
server/main.py        FastAPI demo server — serves 6 sample binary files
tool/main.py          CLI analysis tool — fetches, scans, outputs JSON report
tests/test.py         pytest suite — 24 tests across 5 groups, gates the push
```

The demo server generates three clean files (PNG, JPEG, PDF) and three suspicious ones:
- `suspicious_script.bin` — ELF header with embedded `<script>` XSS payload
- `suspicious_shell.bin`  — ELF header with embedded `/bin/bash` reverse-shell string
- `high_entropy.bin`      — 1,024 bytes of cryptographically random data (~8.0 entropy)

The tool must correctly classify all six: flag the suspicious three, leave the clean three alone.

## Quick Start

```bash
# 1. Install server dependencies
cd server
pip install -r requirements.txt

# 2. Start the demo server (port 3000)
python main.py

# 3. In a second terminal, run the scanner
cd tool
pip install -r requirements.txt
python main.py --target http://localhost:3000

# 4. Run the full test suite
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```
[*] Target: http://localhost:3000
[*] Found 6 file(s) to analyse
[+] clean_png.bin | PNG image | entropy=2.31 | CLEAN
[+] clean_jpeg.bin | JPEG image | entropy=1.87 | CLEAN
[+] clean_pdf.bin | PDF document | entropy=2.14 | CLEAN
[!] suspicious_script.bin | ELF executable | entropy=3.45 | SUSPICIOUS
    >> [HIGH] embedded_script: Found '<script' at offset 0x0028 in suspicious_script.bin
[!] suspicious_shell.bin | ELF executable | entropy=2.98 | SUSPICIOUS
    >> [HIGH] shell_command: Found '/bin/bash' at offset 0x0020 in suspicious_shell.bin
[!] high_entropy.bin | Unknown binary | entropy=7.99 | SUSPICIOUS
    >> [MEDIUM] high_entropy: Shannon entropy 7.99 >= 7.5 in high_entropy.bin (possible encryption or packing)
```

JSON report written to stdout:

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/files/suspicious_script.bin",
      "vulnerability_type": "embedded_script",
      "evidence": "Found '<script' at offset 0x0028 in suspicious_script.bin",
      "severity": "HIGH"
    },
    {
      "endpoint": "/files/suspicious_shell.bin",
      "vulnerability_type": "shell_command",
      "evidence": "Found '/bin/bash' at offset 0x0020 in suspicious_shell.bin",
      "severity": "HIGH"
    },
    {
      "endpoint": "/files/high_entropy.bin",
      "vulnerability_type": "high_entropy",
      "evidence": "Shannon entropy 7.99 >= 7.5 in high_entropy.bin (possible encryption or packing)",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Analysed 6 file(s). Found 3 suspicious pattern(s) across 3 file(s)."
}
```

## Key Takeaways

- **Never trust file extensions** — always inspect the magic bytes at offset 0 to determine true file type before processing
- **High entropy is a red flag** — legitimate executables typically have entropy between 5.0 and 7.0; values above 7.5 strongly suggest a custom packer, UPX compression, or AES-encrypted payload sections
- **Strings analysis works on binaries** — attackers often forget that ASCII strings embedded in binary blobs are trivially detectable; use `strings(1)` or byte-level search as a fast pre-filter before deeper analysis
- **Automate across a corpus** — scanning files one at a time misses patterns; building an API-driven scanner lets you process entire directories or artifact repositories systematically

## Further Reading

- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Gary Kessler's File Signatures Table](https://www.garykessler.net/library/file_sigs.html)
