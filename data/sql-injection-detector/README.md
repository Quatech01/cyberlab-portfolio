# SQL Injection Detector

A hands-on lab that demonstrates SQL injection vulnerabilities in a Node.js/SQLite application and scans for them automatically.

## What This Demonstrates

**SQL injection** occurs when user-supplied input is concatenated directly into a SQL query instead of being passed as a bound parameter. An attacker can manipulate the query structure to:

- **Bypass authentication** — `' OR '1'='1' --` turns a login check into an always-true condition, granting access without a valid password.
- **Exfiltrate data via UNION** — appending `' UNION SELECT ...` returns rows from other tables alongside the intended results.
- **Trigger error messages** — a stray quote causes the database to raise a syntax error; verbose error responses expose table and column names.

The defence is simple and absolute: **never interpolate user input into SQL strings**. Always use parameterized queries (prepared statements with `?` placeholders).

## How It Works

```
server/    Express + better-sqlite3, in-memory SQLite database
           /login          (vulnerable — string concatenation)
           /login/safe     (safe — parameterized query)
           /search         (vulnerable — string concatenation)
           /search/safe    (safe — parameterized query)

tool/      HTTP scanner; probes each endpoint with three payload classes:
           - Error-based     (unbalanced quote → SQL syntax error in response)
           - Auth bypass     (' OR '1'='1' -- → authenticated: true)
           - Union-based     (' UNION SELECT 1,2,3,4 -- → expanded result set)

tests/     node:test suite; starts the server in-process on a random port,
           runs the scanner, and asserts: vulnerable endpoints are flagged,
           safe endpoints produce zero findings, output is valid JSON.
```

## Quick Start

```bash
# Install dependencies
cd server && npm install && cd ..
cd tool   && npm install && cd ..
cd tests  && npm install && cd ..

# Run the demo server
cd server && node index.js

# Run the scanner against it (in a second terminal)
cd tool && node index.js --target http://localhost:3000

# Run the full test suite
cd tests && npm test
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "scan_duration_ms": 42,
  "endpoints_tested": 4,
  "findings": [
    {
      "endpoint": "GET /login (vulnerable)",
      "vulnerability_type": "Error-Based SQLi",
      "payload": "'",
      "evidence": "SQL error leaked in response: \"near 'test': syntax error\"",
      "severity": "HIGH"
    },
    {
      "endpoint": "GET /login (vulnerable)",
      "vulnerability_type": "Authentication Bypass",
      "payload": "' OR '1'='1' --",
      "evidence": "Login succeeded with always-true SQL injection; password was never checked",
      "severity": "CRITICAL"
    },
    {
      "endpoint": "GET /search (vulnerable)",
      "vulnerability_type": "Union-Based SQLi",
      "payload": "' UNION SELECT 1,2,3,4 --",
      "evidence": "Result set grew from 0 to 4 rows — UNION injection exfiltrated extra data",
      "severity": "HIGH"
    }
  ],
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 2,
    "safe_endpoints_confirmed": 2
  }
}
```

## Key Takeaways

1. **String concatenation is the root cause.** One missing parameter placeholder is all it takes to open a critical vulnerability.
2. **Parameterized queries are the complete fix.** The database driver handles escaping internally; the developer never needs to sanitize SQL manually.
3. **Verbose error messages are a secondary vulnerability.** Even if an attacker can't bypass login, a leaked SQL error reveals table structure and aids further attacks.
4. **Detection is straightforward.** Three simple probes — a stray quote, an always-true condition, and a UNION payload — cover the most common SQLi classes.

## Further Reading

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements in SQL Commands](https://cwe.mitre.org/data/definitions/89.html)
