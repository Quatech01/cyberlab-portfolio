# Fee and Payment Management System

A secure full-stack school fee and payment management portal tailored to UK independent schools and colleges. Demonstrates production-ready DevSecOps practices: JWT authentication with refresh token revocation, role-based access control, CSRF double-submit cookie protection, parameterised SQL queries, bcrypt password hashing, Helmet security headers, rate limiting, and idempotent payment processing.

## What This Demonstrates

School fee management involves handling sensitive financial data — tuition invoices, payment records, outstanding balances, and discount calculations — on behalf of students and their families. This project shows how to build an authenticated, role-segregated API that:

- Enforces **row-level data isolation**: parents can only view their own child's invoices and payments; finance officers see everything but cannot modify fee structures; admins have full control
- Uses **JWT access + refresh token architecture**: short-lived (15-minute) access tokens paired with server-side revocable refresh tokens stored as SHA-256 hashes
- Applies **CSRF double-submit cookie protection** on every state-changing request, preventing cross-site forged submissions
- Implements **idempotency keys** on payment endpoints — sending the same key twice returns the original payment instead of charging twice
- Applies **sibling discount logic** server-side when generating invoices, so the discount cannot be manipulated by the client

## How It Works

```
backend/
├── index.js            — Express app factory, DB init, server export
├── config.js           — JWT secret and token expiry constants
├── db/
│   ├── schema.sql      — SQLite table definitions (8 tables, FK constraints)
│   └── seed.js         — Demo users, students, fee schedules, and invoices
├── middleware/
│   ├── authenticate.js — JWT verification middleware
│   ├── csrf.js         — Double-submit cookie CSRF check
│   └── requireRole.js  — Role-based access guard
└── routes/
    ├── auth.js         — Register, login, refresh, logout, /me
    ├── students.js     — Student CRUD (admin) with parent isolation
    ├── fees.js         — Fee schedule CRUD (admin/finance read)
    ├── invoices.js     — Invoice generation with sibling discount, send workflow
    └── payments.js     — Payment processing with idempotency key deduplication

frontend/index.html     — Self-contained SPA: login, register, dashboard
tests/test.js           — 34 node:test tests across 8 groups
```

The server is created by `start(port, dbPath)` which initialises a fresh SQLite database, runs the schema, seeds demo data if empty, and returns an HTTP server. Passing `':memory:'` as `dbPath` gives each test run a clean isolated in-memory database.

## Quick Start

```bash
# Install backend dependencies
cd backend && npm install

# Start the server (port 3000)
node index.js

# In another terminal — run the test suite
cd ../tests && node --test test.js
```

The server will be available at `http://localhost:3000`. Open it in a browser to access the frontend.

**Seed accounts:**

| Role    | Email                    | Password      |
|---------|--------------------------|---------------|
| admin   | admin@school.co.uk       | Admin1234!    |
| finance | finance@school.co.uk     | Finance1234!  |
| parent  | parent1@example.com      | Parent1234!   |
| parent  | parent2@example.com      | Parent2345!   |

## Example API Usage

**Login:**
```bash
curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@school.co.uk","password":"Admin1234!"}' | jq .
```

**Generate an invoice (admin):**
```bash
TOKEN="<access_token_from_login>"
CSRF="<csrf_token_from_cookie>"

curl -s -X POST http://localhost:3000/api/invoices/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: csrf_token=$CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"student_id":1,"term":"Spring","academic_year":"2024-25"}' | jq .
```

**Example invoice response:**
```json
{
  "invoice": {
    "id": 2,
    "student_id": 1,
    "term": "Spring",
    "academic_year": "2024-25",
    "total_amount": 4850.00,
    "outstanding_amount": 4850.00,
    "status": "draft",
    "issued_date": "2026-08-24",
    "due_date": "2026-09-23"
  },
  "items": [
    { "description": "Spring Tuition", "amount": 4500.00 },
    { "description": "Spring Meals", "amount": 350.00 }
  ]
}
```

**Process a payment with idempotency key:**
```bash
curl -s -X POST http://localhost:3000/api/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: csrf_token=$CSRF" \
  -H 'Content-Type: application/json' \
  -d '{
    "invoice_id": 2,
    "amount": 4850.00,
    "payment_method": "direct_debit",
    "idempotency_key": "pay-student1-spring-2024"
  }' | jq .
```

**Example payment response:**
```json
{
  "payment": {
    "id": 1,
    "invoice_id": 2,
    "amount": 4850.00,
    "payment_method": "direct_debit",
    "status": "completed",
    "idempotency_key": "pay-student1-spring-2024",
    "transaction_id": "TXN-1724476800000-4321"
  }
}
```

Sending the same request again returns `{ "payment": {...}, "idempotent": true }` — the same payment, no double charge.

## Key Takeaways

1. **JWT refresh token revocation** — storing only the SHA-256 hash of the refresh token in the DB means a stolen raw token is useless if the server-side entry is revoked (via logout or admin action)

2. **CSRF double-submit cookie** — the frontend reads the `csrf_token` cookie (not HttpOnly) and echoes it in the `X-CSRF-Token` header; the server checks both match, blocking cross-site attackers who can set cookies but cannot read them across origins

3. **Parameterised queries throughout** — `db.prepare('SELECT * FROM users WHERE email = ?').get(email)` passes email as a bound parameter; it is never concatenated into the SQL string

4. **Idempotency keys prevent double-charging** — the `payments` table has a UNIQUE constraint on `idempotency_key`; the insert would fail on a duplicate key, caught before hitting the DB via an explicit lookup that returns the original payment

5. **Row-level RBAC** — SQL queries are written differently per role (`WHERE parent_id = ?` for parents, full table scan for admin/finance); access control lives in the query, not in post-fetch filtering that could be bypassed

6. **Sibling discount computed server-side** — the 10% discount on tuition for siblings is applied during invoice generation; the client cannot inflate or suppress it

## Further Reading

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [JWT Best Practices — RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Payment Idempotency — Stripe Engineering](https://stripe.com/blog/idempotency)
