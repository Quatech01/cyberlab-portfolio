# Universal Credit Eligibility Calculator

A secure full-stack web application that calculates Universal Credit entitlement based on current DWP rates. Built as an educational demonstration of UK public service web applications with production-grade security controls.

## What This Demonstrates

Universal Credit (UC) is the UK's main working-age welfare benefit, replacing six legacy benefits including Jobseeker's Allowance, Housing Benefit, and Tax Credits. The entitlement calculation involves multiple interacting elements: household composition, housing costs, earned income with a work allowance and 55% taper rate, disability additions, capital rules, and the benefit cap.

This application demonstrates how complex, stateful UK government service logic can be implemented securely in a web application — covering multi-step form UX, server-side calculations that users cannot manipulate, role-based data access, and a full DevSecOps security stack.

## How It Works

```
frontend/index.html   — self-contained SPA (no build step, no CDN)
backend/
├── index.js          — Express entry point, helmet, rate limiting, CSRF
├── routes/auth.js    — JWT authentication with bcrypt and refresh tokens
├── routes/assessments.js — UC calculation engine + CRUD
├── routes/admin.js   — admin-only endpoints (stats, audit log)
├── middleware/       — auth guard, CSRF verification
└── db/               — node:sqlite schema, seed data, singleton
tests/test.js         — 32 node:test tests covering all security groups
```

The backend exposes a REST API consumed by the single-page frontend. The frontend never trusts client-supplied amounts — all UC calculations happen server-side from validated inputs. Assessments are stored in SQLite with full audit logging of every data access.

**UC calculation engine** (`backend/routes/assessments.js → calculateUC()`):
1. Reject if savings > £16,000 (capital limit)
2. Compute standard allowance (single under-25 / single 25+ / couple)
3. Add child elements (two-child limit applied)
4. Add disabled child, LCWRA, carer, housing cost, and childcare elements
5. Apply 55% taper on earnings above work allowance (£404 with housing, £673 without)
6. Deduct tariff income on savings between £6,000 and £16,000
7. Apply benefit cap (London/national × family/single), exempt if LCWRA

## Quick Start

**Requirements:** Node.js 22+ (uses built-in `node:sqlite`)

```bash
# Install backend dependencies
cd backend && npm install

# Start the server
node index.js
# → http://127.0.0.1:3000

# Run the tests
cd tests && npm test
```

**Demo accounts:**
| Role  | Email                     | Password   |
|-------|---------------------------|------------|
| Admin | admin@cyberlab.local      | Admin@123  |
| User  | jsmith@example.local      | User@123   |
| User  | mwilson@example.local     | User@123   |

## Example Output

`POST /api/assessments` — single person, 30, £500/month rent, no income:

```json
{
  "id": 1,
  "eligible": true,
  "ineligibility_reason": null,
  "standard_allowance": 368.74,
  "housing_element": 500.00,
  "maximum_uc": 868.74,
  "work_allowance": 0,
  "earned_income_deduction": 0,
  "tariff_income": 0,
  "uc_before_cap": 868.74,
  "benefit_cap": 977.23,
  "benefit_cap_applied": false,
  "monthly_entitlement": 868.74
}
```

Capital over £16,000:

```json
{
  "eligible": false,
  "ineligibility_reason": "capital_limit_exceeded",
  "monthly_entitlement": 0
}
```

## Key Takeaways

- **All calculations are server-side.** Client-submitted payloads are validated with express-validator; the calculation runs on validated integers and floats only. Users cannot submit a manipulated monthly_entitlement value.
- **CSRF double-submit cookie.** The login endpoint sets a readable `csrf_token` cookie. Every state-changing API request must echo it in `X-CSRF-Token`. Header and cookie are compared in middleware before any route logic runs.
- **JWT with revocable refresh tokens.** Access tokens expire in 15 minutes. Refresh tokens are SHA-256 hashed before storage (so a DB breach doesn't expose raw JWTs). Each token includes a random `jti` claim to prevent hash collisions on rapid re-login.
- **Row-level access control.** Users can only read and delete their own assessments, enforced by `WHERE user_id = ?` in every query — not by client-side filtering.
- **Parameterised queries throughout.** All `node:sqlite` operations use bound parameters; no user input is ever concatenated into SQL strings.

## Further Reading

- [How Universal Credit is calculated — GOV.UK](https://www.gov.uk/guidance/how-universal-credit-is-calculated)
- [OWASP Top 10 — A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
