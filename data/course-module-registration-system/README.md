# Course and Module Registration System

A secure full-stack course registration platform for UK sixth forms, colleges, and universities. Students browse modules, manage registrations, and track prerequisites — with automatic clash detection, credit-limit enforcement, and waitlist management. The backend enforces all business rules server-side: no trust is placed in the client.

## What This Demonstrates

This project shows how a real university system balances educational workflow requirements with security engineering:

- **Prerequisite enforcement** — modules with prerequisites can only be registered for after the dependency is satisfied, enforced at the API layer with parameterised SQL, not client-side JavaScript
- **Credit-limit enforcement** — the UK credit framework caps annual enrolment at 120 credits; the server rejects registrations that would exceed this before they reach the database
- **Timetable clash detection** — day/period overlap is checked server-side against the student's active enrolments; no two classes at the same time
- **Waitlist auto-promotion** — when a student withdraws, the next student on the waitlist is atomically enrolled in a single SQL transaction
- **Role-based access control** — students, staff, and admins see different data through SQL-level row isolation, not client-side filtering
- **JWT authentication** — short-lived (15 min) access tokens plus revocable refresh tokens; refresh tokens are SHA-256 hashed in the database so a breach of the token store does not expose usable secrets

## How It Works

```
backend/         Express REST API
  routes/        auth · modules · registrations · admin
  middleware/    JWT auth · CSRF double-submit cookie
  db/            node:sqlite schema · seed data
frontend/        Self-contained SPA (no build step)
tests/           node:test suite — the gate for GitHub push
```

**Security features implemented:**

| Feature | Implementation |
|---|---|
| Security headers | Helmet (CSP, HSTS, X-Content-Type-Options, X-Frame-Options) |
| CSRF protection | Double-submit cookie — `csrf_token` cookie + `X-CSRF-Token` header matched server-side |
| Input validation | express-validator on all user-supplied fields |
| Rate limiting | 100 req/15 min on `/api/auth`, 200 req/min on `/api/*` |
| Parameterised queries | All `node:sqlite` statements use bound parameters — no string concatenation |
| Password hashing | bcrypt at cost factor 12 |
| JWT auth | HS256, 15-minute access tokens, 7-day refresh tokens with server-side revocation |
| RBAC | Middleware checks role before every protected route |

## Quick Start

```bash
# Install backend dependencies
cd backend && npm install

# Start the server (serves both API and frontend on port 3000)
node index.js
# Open http://localhost:3000

# Demo accounts:
# admin     / Admin@1234   (admin)
# dr.smith  / Smith@1234   (staff)
# alice     / Alice@1234   (student — has CS101 completed)
# bob       / Bob@1234     (student)
# charlie   / Charlie@1234 (student)
```

## Running the Tests

```bash
cd tests && npm test
```

Tests cover six groups:
1. **Health** — server starts, `/health` responds
2. **Auth flow** — register, login, wrong password, token validation, refresh, logout
3. **RBAC** — admin access, student blocked from admin endpoints, unauthenticated rejected
4. **Security headers** — Helmet headers verified on every response
5. **Input validation** — empty fields, invalid email, duplicate usernames
6. **Business logic** — prerequisite enforcement, credit limit, clash detection, waitlist auto-promotion, ownership checks

## Example Output

**Prerequisite failure:**
```json
{
  "error": "Prerequisites not met",
  "missing_prerequisites": [
    { "code": "CS101", "title": "Introduction to Programming", "credits": 20 }
  ]
}
```

**Credit limit exceeded:**
```json
{
  "error": "Credit limit exceeded. You have 120 credits enrolled; this module adds 20, which would exceed the 120-credit annual limit.",
  "current_credits": 120,
  "module_credits": 20,
  "credit_limit": 120
}
```

**Waitlist placement:**
```json
{
  "message": "Module is at capacity. Added to waitlist.",
  "waitlist_position": 1,
  "module": { "code": "CS190", "title": "Industrial Placement Prep" }
}
```

## Key Takeaways

1. **Server-side rule enforcement is non-negotiable.** Checking prerequisites or credit limits in JavaScript is worthless — an attacker can bypass client code in seconds. The API must enforce every business rule independently.
2. **SQL transactions prevent partial state.** Waitlist promotion deletes the waitlist entry and inserts the enrolment atomically — without a transaction, a crash between the two operations would leave the database in an inconsistent state.
3. **Parameterised queries are the complete SQLi mitigation.** Every `node:sqlite` statement in this project uses `?` placeholders with bound arguments. User input never touches the SQL string.
4. **JWT refresh tokens need server-side revocation lists.** Access tokens are stateless and expire in 15 minutes, but refresh tokens must be stored (hashed) in the database so logout actually prevents re-authentication.
5. **CSRF matters for cookie-authenticated SPAs.** The double-submit cookie pattern ensures that even if an attacker can trigger cross-site requests, they cannot read the `csrf_token` cookie value to include in the header.

## Further Reading

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [UK Credit Framework (QCF/RQF)](https://www.gov.uk/find-a-regulated-qualification)
