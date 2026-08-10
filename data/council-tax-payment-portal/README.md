# Council Tax Payment Portal

A secure full-stack UK council tax management and payment portal demonstrating eight DevSecOps patterns in a realistic local government context.

## What This Demonstrates

Council tax is the most common interaction UK residents have with local government, making it an ideal domain to illustrate how public sector web applications must balance accessibility with security. This project shows how to combine JWT authentication, role-based access control, CSRF double-submit protection, parameterized SQL queries, and security headers in a single cohesive application — patterns that apply equally to any GDPR-regulated public service platform.

Key security concepts shown:

- **JWT access + refresh token rotation** — 15-minute access tokens, 7-day refresh tokens with SHA-256 hashed storage and server-side revocation
- **CSRF double-submit cookie** — a UUID token is set as a readable cookie on login; every state-changing request must echo it in `X-CSRF-Token`; the server compares header to cookie
- **Role-based access control enforced in middleware** — three roles (`resident`, `admin`, `finance`) with SQL-level data isolation, not just UI hiding
- **Parameterized queries throughout** — no user input is ever concatenated into SQL strings
- **bcrypt cost-12 password hashing** — with constant-time comparison via bcryptjs
- **Helmet security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options on every response
- **express-rate-limit** — 20 req/15 min on auth endpoints, 100 req/min on all API routes
- **express-validator input validation** — UK postcode regex, email normalisation, password complexity rules

## How It Works

```
council-tax-payment-portal/
├── backend/                  Express API server
│   ├── index.js              App entry point, middleware stack
│   ├── db/
│   │   ├── schema.sql        7 tables: users, properties, discounts, payments, schedules, …
│   │   └── index.js          DatabaseSync (node:sqlite) init + seed data
│   ├── middleware/
│   │   └── auth.js           JWT sign/verify, requireAuth, requireRole middleware
│   └── routes/
│       ├── auth.js           register, login, refresh, logout, me
│       ├── properties.js     CRUD + link + band charge calculator
│       ├── payments.js       schedule, history, make payment, arrears report
│       └── discounts.js      apply, list, approve, reject
├── frontend/
│   └── index.html            Self-contained SPA — no CDN, all CSS/JS inline
└── tests/
    └── test.js               33 tests across 6 groups using node:test
```

**Request lifecycle (state-changing):**
1. Client sends `Authorization: Bearer <access_token>` + `X-CSRF-Token: <uuid>` + `Cookie: csrf_token=<uuid>`
2. `authLimiter`/`apiLimiter` check rate limits
3. `csrfProtect` middleware verifies header === cookie
4. `requireAuth` verifies the JWT signature and expiry
5. `requireRole('admin')` checks the `role` claim in the JWT payload
6. Route handler runs a parameterized SQLite query

**Seed data:** 5 users (admin, finance, 3 residents), 5 properties in bands A–H, 1 approved single-person discount, 1 pending student discount, 10-instalment payment schedules for three properties, 2 seeded payments marking April and May as paid for band D property.

## Quick Start

```bash
# Install and start the server
cd backend && npm install
node index.js
# → Server running on http://127.0.0.1:3000

# Open the portal
# → http://127.0.0.1:3000

# Run the full test suite
cd tests && npm test
```

**Demo accounts:**

| Email | Password | Role |
|-------|----------|------|
| admin@oakfield.gov.uk | Admin123! | admin |
| finance@oakfield.gov.uk | Finance123! | finance |
| john.smith@example.com | Resident123! | resident (Band D, 25% discount) |
| jane.doe@example.com | Resident123! | resident (Band B) |

## Example Output

```json
GET /api/properties/my  →  200 OK
{
  "id": 1,
  "council_reference": "OFC-2024-001",
  "address": "12 High Street, Oakfield",
  "postcode": "OA1 1AA",
  "council_tax_band": "D",
  "annual_charge": 218400,
  "approved_discounts": [
    { "discount_type": "single_person", "discount_percentage": 25, "status": "approved" }
  ],
  "total_discount_percentage": 25,
  "net_annual_charge": 163800,
  "monthly_instalment": 16380
}

POST /api/auth/login  →  200 OK
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9…",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9…",
  "csrf_token": "a4b7c3d1-e9f2-…",
  "user": { "id": 3, "username": "john_smith", "role": "resident" }
}

GET /api/payments/arrears  →  200 OK (admin/finance only)
{
  "count": 13,
  "total_owed_pence": 2186980,
  "arrears": [
    { "council_reference": "OFC-2024-002", "due_date": "2026-04-01", "amount": 16987, … }
  ]
}
```

## Key Takeaways

1. **CSRF double-submit is stateless** — no server-side session store is needed; the server just checks that a value the client controls matches in both header and cookie, which a cross-origin attacker cannot replicate due to the same-origin cookie policy.

2. **Row-level SQL filtering is mandatory** — returning `SELECT * FROM properties` and filtering in JavaScript exposes all rows during the fetch; the correct approach is `WHERE user_id = ?` in the query itself.

3. **JWT payload is not secret** — it is Base64-encoded and readable by anyone with the token; never put sensitive data in claims. The signature only proves integrity; confidentiality requires encryption (JWE) or a separate lookup.

4. **UK postcode format validation matters** — a simple regex `^[A-Z]{1,2}[0-9][0-9A-Z]?\s?[0-9][A-Z]{2}$` catches most formatting errors before they reach the database, but canonical validation requires a postcode API.

5. **node:sqlite `DatabaseSync` is synchronous** — it blocks the event loop on each query, which is acceptable for low-concurrency demos and internal tools but requires a connection pool (via `better-sqlite3` with worker threads, or PostgreSQL) for production load.

## Further Reading

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Local Government Finance Act 1992 — council tax framework](https://www.legislation.gov.uk/ukpga/1992/14/contents)
