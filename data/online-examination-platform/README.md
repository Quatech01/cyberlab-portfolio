# Online Examination and Assessment Platform

A secure full-stack online exam platform for UK educational institutions. Teachers create and publish multiple-choice exams with configurable time limits and attempt caps. Students sit exams in a timed browser session; answers are auto-marked on submission. Results are gated — exam content is hidden until a sitting is started, and is_correct flags are never sent to the student client.

## What This Demonstrates

**Server-side exam gating** is the core security concept: a common mistake in online assessment systems is to send all question data (including correct answers) to the browser upfront and rely on client-side JavaScript to hide them. This platform demonstrates the correct approach — questions are only included in API responses when an active sitting exists for that student, and answer keys (`is_correct`) are stripped from every student-facing response at the API layer.

Secondary concepts: JWT authentication with refresh tokens, role-based access control (admin / teacher / student), CSRF double-submit cookie protection, parameterised SQLite queries, bcrypt password hashing, Helmet security headers, and rate limiting on auth endpoints.

## How It Works

```
backend/          Express REST API (Node.js)
  db/             node:sqlite schema, seed data, and DB singleton
  middleware/     JWT auth, RBAC, CSRF validation
  routes/
    auth.js       Register, login, refresh, logout, /me
    exams.js      CRUD for exams and questions (teacher/admin)
    sittings.js   Start sitting, submit answers, view results (student)
    admin.js      Stats, user list, audit log (admin)
frontend/         Self-contained SPA (index.html — all CSS/JS inline)
tests/            node:test suite — 35 tests across 6 groups
```

The database has six tables: `users`, `refresh_tokens`, `exams`, `questions`, `choices`, `exam_sittings`, `answers`, `audit_log`. Foreign keys are enforced and journal mode is WAL.

Key gating logic (in `routes/exams.js`):
- Students receive question data only when an `in_progress` sitting exists for them on that exam
- Choices are returned without `is_correct` for student requests
- Draft exams are invisible to students

## Quick Start

```bash
# Install dependencies
cd backend && npm install

# (Optional) seed demo data
node db/seed.js

# Start the server
npm start
# → http://127.0.0.1:3000

# Demo accounts (after seeding):
#   admin    / Admin1234!
#   msweeney / Teacher1!   (teacher)
#   alice    / Student1!   (student)
```

**Run the tests:**

```bash
cd tests && npm install && npm test
```

## Example API Flow

```bash
# Login
curl -s -c cookies.txt -b cookies.txt \
  -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Student1!"}' | jq .

# Start a sitting (requires CSRF token from login cookie)
CSRF=$(grep csrf_token cookies.txt | awk '{print $7}')
curl -s -b cookies.txt \
  -X POST http://localhost:3000/api/sittings/start \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"exam_id":1}'

# Submit answers
curl -s -b cookies.txt \
  -X POST http://localhost:3000/api/sittings/1/submit \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"answers":[{"question_id":1,"choice_id":3}]}'
```

Example submit response:
```json
{
  "score": 2,
  "total_marks": 2,
  "percentage": 100,
  "passed": true,
  "pass_mark": 60
}
```

## Key Takeaways

- **Never send answer keys to the client.** Strip `is_correct` server-side before serialising question data for student responses.
- **Gate content behind server state.** Whether a student sees questions at all is determined by a database lookup, not a client-side flag.
- **Attempt limits belong on the server.** The client cannot manipulate a `SELECT COUNT(*)` query.
- **CSRF double-submit cookie pattern** — the UUID token is set as a readable (non-HttpOnly) cookie on login; every state-changing request must echo it in the `X-CSRF-Token` header. The server validates both values match.
- **JWT refresh tokens are hashed at rest** — the raw token is never stored; a SHA-256 hash in SQLite allows revocation without exposing the token if the database is leaked.

## Further Reading

- [OWASP Testing for Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [JWT Best Practices — RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
