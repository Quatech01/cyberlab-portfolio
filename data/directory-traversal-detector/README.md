# Directory Traversal Detector

A security scanner that probes file-serving endpoints for path traversal vulnerabilities, paired with a demo server that exposes one vulnerable and one hardened handler side-by-side.

## What This Demonstrates

**Path traversal** (CWE-22) is one of the oldest and most consistently exploited classes of web vulnerability. When a server builds a filesystem path by concatenating a user-supplied string to a base directory — without verifying that the result still sits inside that directory — an attacker can supply sequences like `../` to walk up the directory tree and read arbitrary files the server process can access (configuration files, private keys, credentials, OS files).

This project shows:

- Why `path.join(baseDir, userInput)` is dangerous: `path.join` resolves `../` silently before the path leaves the process, so the caller can escape the intended directory with no encoding tricks.
- How `path.resolve` + a `startsWith` boundary check closes the gap: the full canonical path is computed first, then verified to be a descendant of the intended base directory.
- That URL-encoding (`%2F` for `/`) doesn't bypass application-layer protection — the HTTP server decodes query parameters before they reach the handler — but it also doesn't bypass a properly implemented `path.resolve` check.

## How It Works

```
server/
  public/        ← files the server is allowed to serve
  secret/        ← files that should never be reachable
  index.js       ← Express server
    GET /health             → {"status":"ok"}
    GET /files/unsafe?file= → vulnerable: path.join with no boundary check
    GET /files/safe?file=   → safe: path.resolve + startsWith guard

tool/
  index.js       ← scanner
    sends ../secret/config.txt and URL-encoded variants to both endpoints
    flags any endpoint that responds 200 with secret file content

tests/
  test.js        ← 20 node:test tests covering all 5 groups
```

The scanner probes each endpoint with traversal payloads and inspects the response body for a sentinel string (`SECRET_DATA`) that exists only in files outside the public directory. A 200 response containing that marker is a confirmed vulnerability; 403 or 404 means the traversal was blocked.

## Quick Start

```bash
# Install server dependencies
cd server && npm install && cd ..

# Run the demo server (port 3000)
node server/index.js

# In a second terminal — run the scanner
node tool/index.js --target http://localhost:3000

# Run the test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/files/unsafe",
      "vulnerability_type": "path_traversal",
      "evidence": "Payload '../secret/config.txt' returned HTTP 200 with secret file content",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 1 path traversal vulnerability/vulnerabilities. Affected endpoint(s): /files/unsafe"
}
```

The safe endpoint (`/files/safe`) produces no finding — the scanner correctly identifies it as protected.

## Key Takeaways

1. **`path.join` is not a security boundary.** It normalises paths (resolving `../`) but never enforces that the result stays inside any particular directory.

2. **Canonical path comparison is the correct mitigation.** Compute the full resolved path with `path.resolve(baseDir, userInput)` and reject it unless it starts with `baseDir + path.sep`. This check is immune to `../`, URL-encoding, null bytes, and OS-specific separator tricks because `path.resolve` handles all normalisation before the comparison happens.

3. **Allowlist the expected filenames when the set is small.** If you only serve a fixed list of files, validate the filename against that list before touching the filesystem. Canonical path comparison is the fallback for dynamic directories.

4. **Least-privilege helps at the OS layer.** Even with a traversal flaw, limiting the server process to read-only access on a specific subtree reduces the blast radius of a successful attack.

5. **URL-encoding is not a bypass tool here** — but it demonstrates why frameworks must decode user input before path operations, and why WAF rules that match literal `../` strings are insufficient.

## Further Reading

- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP WSTG: Testing for Path Traversal](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
