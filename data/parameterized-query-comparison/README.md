# Parameterized Query vs Raw Query Comparison

A hands-on demonstration of SQL injection vulnerability through string-concatenated queries,
and how parameterized queries completely eliminate the attack surface.

---

## What This Demonstrates

SQL injection is one of the most common and destructive web vulnerabilities (OWASP Top 10 A03).
It occurs when user-supplied input is embedded directly into a SQL string rather than passed as
a separate parameter. This project shows exactly why that matters:

- A **vulnerable** search endpoint using `f"WHERE username = '{name}'"` lets an attacker return
  every row in the table with the payload `' OR '1'='1`.
- A **vulnerable** login endpoint lets an attacker authenticate as any user — without knowing
  their password — by appending `'--` to bypass the password check entirely.
- The **safe** equivalents use `WHERE username = ?` with bound parameters. SQLite treats the
  entire payload as a literal string value, never as SQL syntax. The injections return nothing.

## How It Works

```
repos/parameterized-query-comparison/
├── server/main.py     FastAPI demo server with 4 endpoints
├── tool/main.py       Scanner that probes the server with injection payloads
└── tests/test.py      28 pytest tests — the gate before any GitHub push
```

**Server endpoints:**

| Endpoint             | Implementation        | Vulnerable? |
|----------------------|-----------------------|-------------|
| `GET /search/unsafe` | string concatenation  | Yes         |
| `GET /search/safe`   | parameterized query   | No          |
| `POST /login/unsafe` | string concatenation  | Yes         |
| `POST /login/safe`   | parameterized query   | No          |

**Scanner logic:**
1. Sends a baseline request for a non-existent user → expects 0 rows / 401
2. Sends `' OR '1'='1` to each search endpoint → more rows than baseline = vulnerable
3. Sends `admin'--` to each login endpoint → HTTP 200 with wrong password = vulnerable
4. Records findings only for endpoints that are actually exploitable

## Quick Start

```bash
# Install dependencies
pip install -r server/requirements.txt
pip install -r tool/requirements.txt
pip install -r tests/requirements.txt

# Start the demo server
python server/main.py

# Run the scanner (in another terminal)
python tool/main.py --target http://localhost:3000

# Run the test suite
cd tests
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/search/unsafe",
      "vulnerability_type": "sql_injection",
      "evidence": "Payload '' OR '1'='1' returned 4 row(s); baseline was 0",
      "severity": "HIGH"
    },
    {
      "endpoint": "/login/unsafe",
      "vulnerability_type": "sql_injection_auth_bypass",
      "evidence": "Authenticated without valid credentials using username='admin'--'",
      "severity": "CRITICAL"
    }
  ],
  "summary": "Found 2 SQL injection issue(s). String-concatenated endpoints are exploitable; parameterized endpoints correctly reject all injection payloads."
}
```

The scanner produces no findings for `/search/safe` and `/login/safe`.

## Key Takeaways

1. **String concatenation is never safe.** No amount of character filtering reliably prevents
   injection — attackers use encoding, alternate comment syntax, and whitespace tricks to bypass
   filters. The only safe approach is to never construct SQL from user input.

2. **Parameterized queries separate code from data.** The database driver sends the SQL
   template and the parameter values independently. The query planner sees the payload as a
   string value — `'admin'--'` is searched for literally, not interpreted as SQL.

3. **Auth bypass is a complete account takeover.** `admin'--` authenticates as any known
   username with zero knowledge of the password. On systems where usernames are predictable
   (admin, root, the user's email) this gives immediate privileged access.

4. **Parameterized queries are zero-cost.** They are often *faster* than string concatenation
   because the database can cache the query plan. There is no performance argument for unsafe
   concatenation.

5. **ORMs use parameterized queries internally.** Django ORM, SQLAlchemy, and most modern
   frameworks parameterize by default — but raw `execute(f"...")` calls bypass that protection
   and are a common source of vulnerabilities in otherwise safe codebases.

## Further Reading

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements in SQL Commands](https://cwe.mitre.org/data/definitions/89.html)
