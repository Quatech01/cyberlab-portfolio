# Social Housing Application Portal

A secure full-stack UK social housing application and allocation management system demonstrating JWT authentication, role-based access control, and the Choice-Based Lettings scheme used by UK councils.

## What This Demonstrates

UK councils manage thousands of social housing applications annually using a **banding system** (A–D) that prioritises need: households facing homelessness or domestic abuse receive the highest priority (Band A), while standard applicants receive Band D. This portal shows how to build an allocation system that:

- Enforces access control at the database-query level, not just the route level
- Calculates housing bands server-side from assessed needs — the client cannot submit its own band
- Uses JWT authentication with short-lived access tokens and revocable refresh tokens
- Applies CSRF double-submit cookie protection on all state-changing endpoints
- Follows the Housing Act 1996 Part VI allocation framework

## How It Works

```
frontend/index.html     — Single-file SPA; applicant and officer dashboards
backend/
  index.js              — Express app factory (no module singletons; each start() is independent)
  db/schema.sql         — SQLite schema: users, applications, properties, cycles, bids, audit_log
  db/seed.js            — Seeds 5 users + 3 properties + 3 open bidding cycles
  middleware/auth.js    — JWT sign/verify, requireRole() middleware
  routes/
    auth.js             — /api/auth/* (register, login, refresh, logout, me)
    applications.js     — /api/applications/* (submit, list, approve, update band)
    properties.js       — /api/properties/* (list, create, get)
    bids.js             — /api/bids/* (list cycles, place bid, award, refuse)
tests/test.js           — 29 node:test assertions covering all 6 test groups
```

The test suite starts the backend with an in-memory SQLite database, seeds realistic data, then runs assertions. Tests are fully deterministic and leave no files on disk.

## Quick Start

```bash
# Install backend dependencies
cd repos/social-housing-application-portal/backend
npm install

# Run the server
npm start
# → http://127.0.0.1:3000

# Run tests (in a separate terminal)
cd ../tests
npm test
```

**Seed accounts:**

| Username  | Email                      | Password      | Role      |
|-----------|----------------------------|---------------|-----------|
| admin     | admin@housing.gov.uk       | Admin123!     | admin     |
| officer1  | officer1@housing.gov.uk    | Officer123!   | officer   |
| alice     | alice@example.com          | Alice123!     | applicant |
| bob       | bob@example.com            | Bob123!       | applicant |
| carol     | carol@example.com          | Carol123!     | applicant |

Alice is in Band A (homeless), Carol is in Band B (overcrowded household of 5), Bob is in Band D (standard applicant).

## Example Output

**POST /api/auth/login**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "applicant"
}
```

**POST /api/applications** (band calculation)
```json
{
  "id": 4,
  "band": "A",
  "bedroom_need": 1,
  "status": "pending"
}
```

**GET /api/bids/property/1** (officer view, priority-ranked)
```json
[
  {
    "id": 1, "username": "alice", "band": "A",
    "bedroom_need": 1, "application_date": "2026-09-26T...",
    "status": "pending"
  }
]
```

## Key Takeaways

1. **Server-side band calculation** — clients submit their needs assessment; the server determines the band. A malicious request cannot self-assign Band A.

2. **JWT refresh token revocation** — refresh tokens are stored as SHA-256 hashes in SQLite. Logging out deletes the hash, preventing token reuse even if the refresh token was captured.

3. **CSRF double-submit cookie** — on login the server sets `csrf_token` as a readable cookie. Every state-changing request must echo it in `X-CSRF-Token` header. An attacker-controlled page cannot read the cookie (SameSite=Strict) and cannot forge the header.

4. **SQL-level row isolation** — applicants see only `WHERE user_id = req.user.id`; officers use a JOIN across all rows. Filtering happens in SQL, not in application code, so it cannot be bypassed.

5. **Housing Act 1996 allocation model** — Band A highest priority (homeless, domestic abuse), Band B high (overcrowded + medical), Band D standard. Priority ordering within band is by application date.

6. **Refusal tracking with suspension** — two refusals triggers `suspension_flag = 1`, blocking further bids. This mirrors real CBL (Choice-Based Lettings) policy.

## Further Reading

- [Housing Act 1996 Part VI — Allocation of Housing](https://www.legislation.gov.uk/ukpga/1996/52/part/VI)
- [DCLG Choice-Based Lettings Code of Guidance](https://www.gov.uk/guidance/allocating-social-housing)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
