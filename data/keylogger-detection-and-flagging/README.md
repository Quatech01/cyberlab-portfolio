# Keylogger Detection and Flagging

A defensive forensics tool that detects behavioural and artefact-based indicators of keylogger activity across four attack surfaces: running processes, registry autorun keys, suspicious files, and unexpected network connections.

---

## What This Demonstrates

Keyloggers are a class of malware that silently record keyboard input to harvest credentials, intercept sensitive communications, or enable persistent espionage. They leave traces across multiple layers of a system:

| Layer | Indicator examples |
|---|---|
| **Processes** | Known keylogger executable names (`ardamax.exe`, `hook32.dll`) |
| **Registry** | Autorun keys under `HKCU\...\Run` with keyboard-capture naming |
| **Files** | Keystroke log dumps in `%TEMP%` (`keystrokes.log`, `kl_capture.dat`) |
| **Network** | Outbound connections to unknown IPs, especially on non-standard ports |

Effective detection requires cross-referencing all four layers — a single clean layer does not exonerate a system. The tool assigns severity ratings (HIGH / MEDIUM / LOW) so a defender can prioritise remediation.

---

## How It Works

```
┌─────────────────────────────────────────────┐
│              Demo Server (FastAPI)           │
│                                              │
│  GET /scan/processes      ← seeded with      │
│  GET /scan/registry         known indicators │
│  GET /scan/files                             │
│  GET /scan/connections                       │
│                                              │
│  GET /scan/processes/safe  ← clean baselines │
│  GET /scan/registry/safe     for false-      │
│  GET /scan/files/safe        positive tests  │
│  GET /scan/connections/safe                  │
└────────────────────┬────────────────────────┘
                     │ HTTP (localhost only)
┌────────────────────▼────────────────────────┐
│           Detection Tool (Python)            │
│                                              │
│  1. check_processes()  → known name lookup   │
│  2. check_registry()   → autorun + path scan │
│  3. check_files()      → filename patterns   │
│  4. check_connections()→ IP + port analysis  │
│                                              │
│  Outputs: structured JSON threat report      │
└─────────────────────────────────────────────┘
```

The **demo server** intentionally seeds its vulnerable endpoints with realistic keylogger artefacts:
- Process list includes `hook32.dll` and `ardamax.exe`
- Registry includes a `KeyCapture` autorun key and an executable launching from `C:\Temp`
- File list includes `kl_capture.dat` and `keystrokes.log` in a temp directory
- Network connections include an unknown IP on port 4444 (classic C2 channel)

The **detection tool** applies a rule set against each layer and emits a structured JSON report. The **test suite** verifies all four categories of true positives are caught, safe endpoints are never falsely flagged, the output schema is always valid, and an unreachable server is handled gracefully.

---

## Quick Start

**Requirements:** Python 3.11+

```bash
# Install server dependencies
cd server
pip install -r requirements.txt

# Run the demo server
python main.py
# Server starts on http://127.0.0.1:3000

# In a second terminal — run the detection tool
cd tool
pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the full test suite
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

---

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/scan/processes",
      "vulnerability_type": "known_keylogger_process",
      "evidence": "Process 'hook32.dll' (PID 3120) matches a known keylogger signature",
      "severity": "HIGH"
    },
    {
      "endpoint": "/scan/processes",
      "vulnerability_type": "known_keylogger_process",
      "evidence": "Process 'ardamax.exe' (PID 3244) matches a known keylogger signature",
      "severity": "HIGH"
    },
    {
      "endpoint": "/scan/registry",
      "vulnerability_type": "keylogger_autorun_registry",
      "evidence": "Autorun key 'HKCU\\...\\Run\\KeyCapture' value 'KeyCapture' → 'C:\\Users\\Public\\kc.exe --silent' contains a keyboard-capture naming pattern",
      "severity": "HIGH"
    },
    {
      "endpoint": "/scan/registry",
      "vulnerability_type": "suspicious_autorun_location",
      "evidence": "Autorun key 'HKCU\\...\\Run\\Updater' → 'C:\\Temp\\kl_service.exe' launches an executable from a suspicious temporary directory",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/scan/files",
      "vulnerability_type": "keylogger_artefact_file",
      "evidence": "File 'C:\\Users\\Public\\AppData\\Local\\Temp\\kl_capture.dat' has a keyboard-capture naming pattern indicative of a keystroke log or capture dump",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/scan/files",
      "vulnerability_type": "keylogger_artefact_file",
      "evidence": "File 'C:\\Users\\Public\\AppData\\Local\\Temp\\keystrokes.log' has a keyboard-capture naming pattern indicative of a keystroke log or capture dump",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/scan/connections",
      "vulnerability_type": "unknown_outbound_connection",
      "evidence": "Outbound connection to 198.51.100.77:443 — IP does not match any recognised cloud-provider range",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/scan/connections",
      "vulnerability_type": "suspicious_c2_connection",
      "evidence": "Outbound connection to 203.0.113.42:4444 — unknown destination on a non-standard port (possible C2 channel)",
      "severity": "HIGH"
    }
  ],
  "summary": "8 keylogger indicator(s) detected (4 HIGH, 4 MEDIUM, 0 LOW)"
}
```

---

## Key Takeaways

1. **Layered detection catches what single-layer checks miss.** A keylogger that renames its process to something generic still leaves a registry autorun key and a file dump.

2. **Autorun registry keys are a primary persistence mechanism.** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` requires no admin rights to write to and survives reboots — always audit it.

3. **Temp directories are a common staging ground.** Keyloggers write capture files to `%TEMP%` because the path is always writable. File path scanning in forensic triage should always include temp directories.

4. **Non-standard outbound ports signal C2 activity.** Legitimate applications use 443 (HTTPS) or 80 (HTTP). An unknown IP communicating on port 4444 or similar is a high-confidence indicator of a command-and-control channel.

5. **False-positive discipline matters.** A noisy detector that flags `chrome.exe` and `OneDrive` will be ignored. Rule precision — exact name matching for HIGH, pattern matching for MEDIUM — keeps alert fatigue low.

---

## Further Reading

- [MITRE ATT&CK T1056.001 — Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1071 — Application Layer Protocol (C2)](https://attack.mitre.org/techniques/T1071/)
