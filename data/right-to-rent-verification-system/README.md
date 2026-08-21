# Right to Rent Verification System

A secure full-stack UK Right to Rent compliance management system for landlords. Built with Express, node:sqlite, and a self-contained SPA frontend demonstrating JWT authentication, RBAC, CSRF protection, and all eight DevSecOps controls from the OWASP Top 10 perspective.

## What This Demonstrates

UK landlords have a legal obligation under the Immigration Act 2014 to verify that prospective tenants have the right to rent property in England. Failure to do so carries civil penalties of up to £20,000 per tenant. This system demonstrates:

- How to model time-sensitive compliance workflows with follow-up dates (28 days before permission expiry)
- Secure multi-role access so each landlord sees only their own properties and tenants
- How server-side status computation (`compliant / expiring_soon / expired`) prevents client-side manipulation
- All eight DevSecOps controls wired into a real-world application: helmet headers, CSRF double-submit cookies, express-validator input validation, rate limiting, parameterized queries, bcrypt hashing, JWT with revocable refresh tokens, and RBAC middleware

## How It Works

```
backend/           Express REST API
  routes/auth.js   Register, login, refresh, logout, /me
  routes/tenants.js Properties and tenants CRUD
  routes/checks.js  Right-to-rent check records, alerts, certificates
  middleware/auth.js JWT helpers, requireAuth, requireRole, requireCsrf
  db/              node:sqlite schema, seed, init
frontend/
  index.html       Self-contained SPA — all CSS and JS inline, no CDN
tests/
  test.js          32 node:test tests gating the GitHub push
```

The server seeds three landlord accounts and five tenants across three properties. Time-limited tenants (non-British/Irish nationals) get a follow-up date automatically calculated as 28 days before their permission expiry date — matching Home Office guidance.

## Quick Start

```bash
cd backend && npm install
node index.js
# Open http://127.0.0.1:3000
# Login: john_smith / Landlord@Pass456!  (landlord)
#        admin      / Admin@Secure123!   (admin)
```

## Run Tests

```bash
cd tests
node --test test.js
```

## Example Output

```json
GET /api/checks/certificate/2

{
  "certificate_date": "2026-08-22",
  "tenant": {
    "full_name": "Amir Hassan",
    "nationality": "Egyptian",
    "date_of_birth": "1985-08-22"
  },
  "property": {
    "address": "42 Oak Street, London",
    "postcode": "E1 6RF"
  },
  "check": {
    "check_date": "2025-01-10",
    "document_type": "biometric_residence_permit",
    "document_description": "BRP card (time-limited leave to remain)",
    "permission_type": "time_limited",
    "permission_expiry_date": "2026-09-10",
    "follow_up_date": "2026-08-13"
  },
  "status": "expiring_soon",
  "compliant": true,
  "compliance_statement": "Right to Rent confirmed. Documents verified as per Immigration Act 2014."
}
```

## Key Takeaways

- **Follow-up date automation**: storing `permission_expiry_date - 28 days` as `follow_up_date` removes human error from compliance calendars
- **Server-side status computation**: `compliant / expiring_soon / expired` is computed fresh on each API response from the stored expiry date — never stored or trusted from the client
- **CSRF double-submit cookie**: the `csrf_token` UUID is set as a readable (non-HttpOnly) cookie on login; every state-changing request must echo it in the `X-CSRF-Token` header; the server compares both — an attacker on another origin cannot read the cookie value
- **Parameterized queries throughout**: every `db.prepare('...?...').run(value)` call keeps SQL and data separate at the driver level

## Further Reading

- [Home Office: Right to Rent guidance](https://www.gov.uk/government/collections/landlords-immigration-right-to-rent-checks)
- [Immigration Act 2014 — Part 3 (Residential Tenancies)](https://www.legislation.gov.uk/ukpga/2014/22/part/3)
- [OWASP: Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP: CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
