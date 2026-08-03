# Digital Attendance Tracking System

A secure full-stack attendance management system for UK schools and colleges, built with Express, SQLite, and vanilla JavaScript.

## What This Demonstrates

This project shows how to build a production-grade attendance tracking application with layered security controls. The app handles sensitive student data, so it implements the full DevSecOps stack: JWT authentication with refresh token revocation, role-based access control enforced at the SQL layer, CSRF double-submit cookie protection, Helmet security headers, rate limiting, and input validation via express-validator.

The attendance domain also showcases important UK statutory compliance concepts: tracking the 90% persistent absence threshold defined by the Department for Education, differentiating between present, late, absent, and authorised absence statuses, and maintaining a tamper-resistant audit log of every data access and attendance mark.

## How It Works

```
backend/           Express REST API
  db/              SQLite schema (node:sqlite) + seed data
  middleware/      JWT verification, RBAC, CSRF double-submit
  routes/          auth, students, classes, attendance, reports
frontend/          Self-contained SPA (no build step)
tests/             node:test integration suite (gates GitHub push)
```

The demo server seeds three roles on startup:
- **admin** (Sarah Thompson) — full access, audit log, low-attendance reports
- **teacher** (Radha Patel / Emmanuel Okafor) — see own classes, mark registers
- **student** (Alice Jones et al.) — view own attendance only

Row-level data isolation is enforced in SQL queries, not client-side: teachers run a JOIN against their own `teacher_id`, students run a WHERE against their own `user_id`.

## Quick Start

```bash
# Install backend dependencies
cd backend && npm install

# Start the server (seeds demo data automatically)
npm start
# → http://127.0.0.1:3000

# Run tests (separate terminal)
cd ../tests && npm test
```

### Demo credentials

| Role    | Username   | Password    |
|---------|------------|-------------|
| Admin   | admin      | Admin1234!  |
| Teacher | ms_patel   | Teacher1!   |
| Teacher | mr_okafor  | Teacher2!   |
| Student | alice_y10  | Student1!   |

## Example Output

`GET /api/students/:id/attendance` response:

```json
{
  "student_id": 1,
  "records": [
    { "lesson_date": "2026-08-02", "period": "1", "class_name": "10A Maths", "subject": "Mathematics", "status": "present" },
    { "lesson_date": "2026-08-01", "period": "1", "class_name": "10A Maths", "subject": "Mathematics", "status": "present" }
  ],
  "total": 5,
  "present": 5,
  "percentage": 100,
  "low_attendance": false
}
```

## Security Features

| Feature | Implementation |
|---------|---------------|
| Authentication | JWT HS256, access token (15 min) + refresh token (7 days, DB-revocable) |
| CSRF protection | Double-submit cookie — `csrf_token` cookie matched against `X-CSRF-Token` header |
| Security headers | Helmet: CSP, HSTS, X-Content-Type-Options, X-Frame-Options |
| Rate limiting | Auth: 20 req/15 min · API: 100 req/min |
| Input validation | express-validator on all routes — rejects malformed email, empty fields, invalid enums |
| SQL injection | node:sqlite parameterized queries throughout — no string concatenation |
| Password hashing | bcryptjs cost factor 12 |
| RBAC | SQL-level row filtering per role; 403 returned for privilege violations |

## Key Takeaways

1. **CSRF is still relevant with JWT** — although Bearer tokens aren't automatically attached by browsers, a CSRF token ensures that only your own frontend can mutate state.
2. **Row-level access control must be in SQL** — filtering in application code after fetching all rows is dangerous; the DB should never return rows the caller cannot see.
3. **Persistent absence (below 90%) is a UK statutory threshold** — tracking it server-side prevents students or parents from manipulating the calculation.
4. **Refresh token revocation requires server-side storage** — the `refresh_tokens` table stores a revoked flag so logout actually invalidates the session, unlike stateless JWT alone.

## Further Reading

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [DfE School Attendance Guidance](https://www.gov.uk/government/publications/working-together-to-improve-school-attendance)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
