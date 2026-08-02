# GP Appointment Booking System

A secure full-stack NHS-style GP appointment booking platform demonstrating JWT authentication, role-based access control, CSRF protection, and parameterised database queries in a Node.js/Express application.

## What This Demonstrates

This project covers the eight core DevSecOps controls every web application needs before going to production:

- **JWT authentication** with short-lived access tokens (15 min) and revocable refresh tokens stored in SQLite
- **bcrypt password hashing** at cost factor 12 — computationally expensive to crack
- **Role-based access control (RBAC)** across four roles: `admin`, `gp`, `patient`, and the middleware that enforces it
- **CSRF protection** via a double-submit cookie pattern — state-changing requests require a matching `X-CSRF-Token` header and `csrf_token` cookie
- **Security headers** via Helmet — CSP, HSTS, X-Content-Type-Options, X-Frame-Options
- **Rate limiting** on auth (20 req/15 min) and API (100 req/min) routes
- **Parameterised queries** throughout — user input never touches SQL string construction
- **Input validation** with `express-validator` — email format, password strength, field length limits

## How It Works

```
backend/           Express REST API
  db/              node:sqlite database (auto-created on first run)
    schema.sql     Table definitions: users, gps, availability_slots, appointments, audit_log
    seed.js        Inserts 3 GPs, 4 patient accounts, and 7 days of availability slots
  middleware/      auth.js — JWT helpers, requireAuth, requireRole, CSRF guard
  routes/          authRoutes, gpRoutes, appointmentRoutes
frontend/          Self-contained SPA (no build step, no CDN dependencies)
tests/             31 node:test tests covering all 6 groups
```

The demo server starts on port 3000, auto-seeds the database, and serves the frontend as static files. The backend API lives at `/api/*`.

## Quick Start

```bash
# Install and start the backend
cd backend && npm install && node index.js

# Open the frontend
# Visit http://127.0.0.1:3000 in your browser
```

Demo accounts:

| Role    | Email                          | Password      |
|---------|-------------------------------|---------------|
| admin   | admin@nhsdemo.local            | Admin1234!    |
| patient | john.smith@patient.local       | Patient1234!  |
| gp      | sarah.mitchell@nhsdemo.local   | Doctor1234!   |

## Running the Tests

```bash
cd tests && npm test
```

All 31 tests must pass. They cover:

1. **Health** — server starts, `/health` returns 200
2. **Auth flow** — register, login, wrong password, token refresh, duplicate account
3. **RBAC** — admin endpoints blocked for patients, unauthenticated requests return 401
4. **Security headers** — Helmet headers present on every response
5. **Input validation** — empty fields, invalid email, SQL injection strings, missing CSRF token
6. **Business logic** — GP listing, slot availability, appointment booking, cancellation ownership, admin audit log

## Example Output

```json
GET /api/gps/1/slots
[
  { "id": 3, "slot_date": "2026-08-03", "slot_time": "09:00", "duration_minutes": 10, "is_booked": 0 },
  { "id": 4, "slot_date": "2026-08-03", "slot_time": "09:10", "duration_minutes": 10, "is_booked": 0 }
]

POST /api/appointments  (with valid JWT + CSRF token)
{ "message": "Appointment booked", "booking_reference": "GP-A1B2C3D4", "id": 1 }
```

## Key Takeaways

- A 15-minute access token expiry limits the damage if a token is stolen — the attacker's window is short and there is no way to extend it without the refresh token.
- Refresh tokens are stored as SHA-256 hashes in the database so a database breach does not expose working tokens.
- CSRF protection using the double-submit cookie pattern is stateless — no server-side session required — but still blocks cross-origin form submissions because an attacker's page cannot read the `csrf_token` cookie value.
- `express-validator` validates at the API boundary before any database code runs, so injection strings never reach `db.prepare()`.
- Row-level ownership checks in the appointment cancellation route (re-fetching the record and comparing `patient_id` to `req.user.sub`) prevent IDOR — a patient cannot cancel another patient's appointment even if they know the ID.
- The audit log records every login, booking, and cancellation with a timestamp and IP address for incident response.

## Further Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
