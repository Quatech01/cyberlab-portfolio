# Planning Permission Application Tracker

A secure full-stack UK planning permission tracking and management system, built as an educational demonstration of modern web security practices.

## What This Demonstrates

Planning authorities process thousands of applications with strict statutory deadlines and public transparency requirements — a perfect environment to demonstrate layered security. This project shows how role-based access control, parameterized SQL, JWT authentication, and DevSecOps tooling work together in a real-world scenario where some data is public (decision notices), some is applicant-only (personal details), and some is restricted to officers and administrators (internal case notes, audit logs).

The 8-week statutory determination deadline (Town and Country Planning Act 1990) is enforced server-side so deadline calculation is never trusted from the client.

## How It Works

```
backend/        Express API — JWT auth, SQLite via node:sqlite, all 8 DevSecOps controls
  routes/       auth, applications, decisions, admin
  middleware/   JWT verification, RBAC, CSRF double-submit
  db/           schema.sql (6 tables) + seed.js (5 demo users, 5 applications)
frontend/       Single self-contained HTML/CSS/JS SPA — no build step, no CDN
tests/          node:test suite — 23 tests across 6 groups
```

**Roles:**
- `applicant` — submit applications, track own status
- `officer` — manage all applications, add consultee responses and notes, issue decisions
- `admin` — all officer permissions plus audit log and user management

**Security controls applied:**
1. **Helmet** — Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options on every response
2. **CSRF** — double-submit cookie; `csrf_token` cookie set on login; every POST/PUT/DELETE must echo it in `X-CSRF-Token` header
3. **Input validation** — express-validator on all API inputs; UK postcode regex enforced; SQL injection strings stored safely via parameterized queries
4. **Rate limiting** — auth routes: 20 req/15 min; API routes: 100 req/min
5. **Parameterized queries** — every SQL statement uses `db.prepare()` with bound parameters; no string concatenation
6. **Password hashing** — bcrypt at cost factor 12; never stored or logged in plaintext
7. **JWT auth** — 15-minute access tokens + 7-day SHA-256-hashed revocable refresh tokens in SQLite
8. **RBAC** — `requireRole()` middleware enforces role checks server-side; SQL-level row isolation for applicant data

## Quick Start

```bash
cd backend
npm install
node index.js        # starts on port 3000

# Optional: load demo data
node db/seed.js
```

Seed credentials:
| Email | Password | Role |
|---|---|---|
| admin@planning.example | Admin123! | admin |
| officer@planning.example | Officer123! | officer |
| alice@example.com | Alice123! | applicant |
| bob@example.com | Bob123! | applicant |

Visit http://localhost:3000 to use the SPA frontend.

## Running the Scanner Tool

There is no standalone CLI tool for this project — it is a full-stack application. Run the test suite to exercise all security properties:

```bash
cd tests
npm test
```

## Running Tests

```bash
cd tests
npm test
```

Expected output: 23 tests, 0 failures.

## Example API Output

**POST /api/applications** (submit new application):
```json
{
  "id": 6,
  "reference_number": "PP-2026-000006",
  "applicant_id": 3,
  "property_address": "42 Test Lane, Birmingham",
  "postcode": "B1 1BB",
  "description_of_works": "Two storey side extension with pitched roof to match existing dwelling.",
  "application_type": "householder",
  "status": "submitted",
  "submitted_at": "2026-09-02T10:00:00.000Z",
  "determination_deadline": "2026-10-28T10:00:00.000Z",
  "assigned_officer_id": null
}
```

**GET /api/decisions/:id** (public decision notice):
```json
{
  "id": 1,
  "application_id": 4,
  "decision": "approved",
  "decision_date": "2026-09-02T10:00:00.000Z",
  "conditions": "The works shall be carried out using materials which match in appearance those used in the original building.",
  "reasons": "The proposed works preserve the character and appearance of the listed building in accordance with Local Plan Policy DM27.",
  "officer_name": "James Smith",
  "reference_number": "PP-2026-000004",
  "property_address": "77 Manor Road, Bristol",
  "application_type": "listed_building"
}
```

## Key Takeaways

- **Decision notices are public by design** — once issued, they are accessible without authentication, mirroring the statutory public register requirement
- **Applicant personal details (name, email) are never returned to unauthenticated requests** — the API returns a different field set based on role, implemented with separate SQL projections not client-side filtering
- **The 8-week deadline is computed server-side** at submission time and stored; the client cannot influence it
- **CSRF double-submit cookie** works even for stateless JWT APIs — the browser's same-origin policy prevents cross-origin attackers from reading the cookie value
- **Parameterized queries** mean SQL injection strings in description fields are stored as harmless text, never executed

## Further Reading

- [OWASP RBAC Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Town and Country Planning Act 1990 — 8-week determination period](https://www.legislation.gov.uk/ukpga/1990/8/section/78)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
