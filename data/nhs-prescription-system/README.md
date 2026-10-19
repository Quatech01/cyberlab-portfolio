# NHS Prescription Management System

A full-stack electronic prescription management system modelled on the NHS Electronic Prescription Service (EPS). GPs issue prescriptions, patients request repeats online, pharmacists process and dispense — with a full DevSecOps security stack throughout.

## What This Demonstrates

How healthcare applications handle sensitive data with multiple distinct user roles, each with strictly enforced permissions. The system shows JWT-based authentication, role-based access control (patient / GP / pharmacist / admin), controlled drug dual-authorisation workflows, parameterized SQL queries, CSRF protection, bcrypt password hashing, rate limiting, and security response headers — all working together in a realistic domain.

## How It Works

```
backend/          Express API — JWT auth, RBAC, SQLite via node:sqlite
  routes/         auth.js  prescriptions.js  medications.js  patients.js
  middleware/     auth.js  (authenticate, requireRole, csrfProtect)
  db/             schema.sql  init.js  seed.js
frontend/         Single-file SPA — role-aware dashboard, no external CDN
tests/            29 node:test assertions covering all 6 groups
```

**Auth flow:** Login returns `access_token` (15-min JWT), `refresh_token` (7-day, server-revocable), and `csrf_token` (UUID tied to the refresh token record). Every state-changing API call must include `X-CSRF-Token`. Refresh tokens are stored in SQLite and can be revoked on logout.

**RBAC enforcement:**
| Role | Can do |
|---|---|
| patient | view own prescriptions, request repeats |
| gp | issue prescriptions, view prescriptions they wrote |
| pharmacist | view issued prescriptions queue, mark dispensed |
| admin | full read access across all records |

**Controlled drugs:** Medications with `schedule = 2` (morphine, diazepam) require a second GP or admin to authorize before the prescription moves to `issued` status — a direct model of Schedule 2 CD counter-signing requirements.

## Quick Start

```bash
cd backend && npm install
node index.js
# Open http://127.0.0.1:3000
```

Demo accounts (passwords shown):

| Email | Password | Role |
|---|---|---|
| admin@nhsdemo.local | Admin123! | admin |
| dr.smith@nhsdemo.local | Doctor123! | gp |
| jane@pharmacy.local | Pharm123! | pharmacist |
| alice@example.local | Patient123! | patient |
| bob@example.local | Patient123! | patient |

## Run Tests

```bash
cd tests && node --test test.js
```

All 29 tests should pass. They cover server health, the full auth flow, RBAC enforcement, security headers, input validation (including SQL injection resistance), and prescription business logic (repeat limits, CD status, CSRF enforcement, dispense idempotency).

## Example API Interaction

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dr.smith@nhsdemo.local","password":"Doctor123!"}' | jq -r .access_token)

CSRF=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dr.smith@nhsdemo.local","password":"Doctor123!"}' | jq -r .csrf_token)

# Issue a prescription
curl -X POST http://localhost:3000/api/prescriptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"patient_id":5,"medication_id":1,"dose":"1 capsule TDS","quantity":21,"repeats_allowed":2}'
```

```json
{
  "prescription": {
    "id": 6,
    "patient_id": 5,
    "prescriber_id": 2,
    "medication_id": 1,
    "dose": "1 capsule TDS",
    "quantity": 21,
    "repeats_allowed": 2,
    "repeats_used": 0,
    "status": "issued"
  }
}
```

## Key Takeaways

- **RBAC must be server-side.** Client role claims in JWTs are only trustworthy if the server re-validates them on every request — never skip the middleware.
- **CSRF protection pairs with JWT.** Bearer tokens in `Authorization` headers resist CSRF by default, but when a session or cookie is involved you need an explicit token. This demo shows the explicit pattern.
- **Controlled drug workflows are a real compliance requirement.** The dual-authorization gate mirrors the legal requirement for Schedule 2 CDs under the Misuse of Drugs Regulations 2001.
- **Parameterized queries are non-negotiable.** Every DB call in this project uses `db.prepare(...).get/run(params)` — never string concatenation.
- **Short-lived access tokens + revocable refresh tokens** give you the best of both: stateless request validation without losing the ability to invalidate sessions.

## Further Reading

- [NHS Digital — Electronic Prescription Service](https://digital.nhs.uk/services/electronic-prescription-service)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP — CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Misuse of Drugs Regulations 2001 — Schedule 2 requirements](https://www.legislation.gov.uk/uksi/2001/3998/schedule/2)
