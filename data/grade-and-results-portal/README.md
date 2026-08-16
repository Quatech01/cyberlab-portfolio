# Grade and Results Portal

A secure full-stack grade management system for UK schools, demonstrating JWT authentication, role-based access control, and eight DevSecOps security controls.

## What This Demonstrates

This project shows how to build a production-grade web application that protects sensitive student data. UK schools handle GCSE and A-Level results under GDPR obligations, meaning access controls must be watertight — a student must never see another student's grades, and a teacher must never be able to edit marks for a subject they do not teach.

The grade calculation engine converts raw marks into UK grade letters automatically: GCSE 9-1 (where 85%+ earns a 9) and A-Level A\*–U (where 90%+ earns an A\*). At-risk detection flags students whose current average falls more than one grade below their target.

## How It Works

```
frontend/index.html     — self-contained SPA (no build step, all JS inline)
backend/
  index.js              — Express app: Helmet, rate limiting, CSRF, routes
  middleware/
    auth.js             — JWT verification middleware
    rbac.js             — role gating and CSRF double-submit check
  routes/
    auth.js             — register, login, refresh, logout, /me
    subjects.js         — subject CRUD and student enrollment
    grades.js           — grade entry, update, delete, progress reports
  db/
    schema.sql          — SQLite tables (users, subjects, assessments, grades, audit_log)
    init.js             — node:sqlite setup with WAL mode and foreign keys
    seed.js             — demo data: 2 teachers, 2 students, 1 parent, 3 subjects, 5 grades
tests/test.js           — 25 node:test assertions across 6 groups
```

**Request flow:**
1. Browser hits `/api/auth/login` → receives access token (JWT, 15 min) + refresh token (7 days, SHA-256 hashed in DB)
2. `csrf_token` cookie set on login; all state-changing requests must echo it in `X-CSRF-Token` header
3. Protected routes verify JWT via `authenticate` middleware, then role via `requireRole`
4. Grade writes are audit-logged with user ID and IP address

## Quick Start

```bash
# Install backend dependencies
cd backend && npm install

# Start the server (creates SQLite DB and seeds demo data automatically)
node index.js
# → http://localhost:3000

# Demo accounts
# admin / Admin@1234     (can manage everything)
# ms_johnson / Teacher@1234  (teacher of Maths and English)
# mr_patel / Teacher@1234    (teacher of Science)
# alice_w / Student@1234     (student enrolled in all three subjects)
# parent_alice / Parent@1234(parent of alice_w)

# Run tests
cd ../tests && npm install && npm test
```

## Example Output

**POST /api/auth/login** response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "teacher",
  "full_name": "Ms. E. Johnson"
}
```

**GET /api/grades/students/4/report** (student progress report):
```json
{
  "student": { "id": 4, "full_name": "Alice Williams", "year_group": "Year 11" },
  "report": [
    {
      "subject": "Mathematics",
      "grade_scheme": "gcse",
      "target_grade": "7",
      "current_grade": "8",
      "average_percentage": 83,
      "at_risk": false,
      "assessments_count": 2
    },
    {
      "subject": "Combined Science",
      "grade_scheme": "gcse",
      "target_grade": "6",
      "current_grade": "6",
      "average_percentage": 75,
      "at_risk": false,
      "assessments_count": 1
    }
  ]
}
```

## Key Takeaways

- **JWT access + refresh tokens**: access tokens expire in 15 minutes; refresh tokens are stored as SHA-256 hashes in SQLite so they can be revoked server-side at logout
- **CSRF double-submit cookie**: a UUID is set as a readable cookie on login and must be echoed in `X-CSRF-Token` on every POST/PUT/DELETE — prevents cross-site form submissions
- **Row-level RBAC**: teachers can only read and write data for subjects they own; students can only read their own grades; parents can only read their linked child's data — enforced in SQL, not client-side
- **UK grade schemes**: GCSE 9-1 and A-Level A\*-U calculated server-side from raw marks — the client never sends a grade letter, only marks awarded
- **Parameterized queries throughout**: `node:sqlite` prepared statements used on every DB operation; no user input is ever concatenated into SQL

## Further Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
