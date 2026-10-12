# Library Management System

A secure full-stack library management system for UK schools and colleges. Students browse the catalogue, borrow and return books, and manage reservations from a self-contained SPA. Librarians manage returns and overdue items. Admins control user roles and review the audit trail.

## What This Demonstrates

**Authentication and authorisation in a multi-role web application.** The system implements:

- **JWT access + refresh tokens** with a 15-minute access token window and server-side revocation for refresh tokens, preventing long-lived credential abuse
- **CSRF double-submit cookie pattern** — a UUID token is embedded in the signed JWT and must be echoed in every state-changing request; forged cross-site requests lack this value
- **Role-based access control (RBAC)** with three roles: `student`, `librarian`, `admin` — middleware blocks routes before any business logic runs
- **Row-level isolation** — students can only see and act on their own loans and reservations; librarians see all
- **Input validation** using express-validator on every API boundary
- **Parameterised queries** throughout — no raw string concatenation
- **bcrypt** password hashing at cost 12 with constant-time comparison
- **Helmet** security headers — CSP, HSTS, X-Content-Type-Options, X-Frame-Options on every response
- **Rate limiting** on auth endpoints (20 req / 15 min) and the general API (100 req / min)
- **Audit log** recording every login, borrow, return, and role change

## How It Works

```
backend/         Express API (JWT auth, RBAC, SQLite via node:sqlite)
  routes/        auth.js, books.js, loans.js, reservations.js, admin.js
  middleware/    auth.js (JWT verify), rbac.js (role guard), csrf.js (double-submit)
  db/            schema.sql, seed.js (admin/librarian/student + 10 books), index.js
frontend/        Single self-contained SPA — all CSS and JS inline
tests/           26 node:test assertions covering all 6 test groups
```

The `start(port)` export lets the test file launch the server on a random port without any network conflicts.

## Quick Start

```bash
# Install backend dependencies
cd backend && npm install && cd ..

# Run the server
cd backend && node index.js
# Visit http://localhost:3000

# Default accounts (created by seed):
#   admin@library.ac.uk     Admin123!    role: admin
#   librarian@library.ac.uk Lib123!      role: librarian
#   student@library.ac.uk   Student123!  role: student

# Run the security tool (scan the running server)
cd tool && npm install && node index.js --target http://localhost:3000

# Run all tests
cd tests && npm test
```

## Example Output

```
GET /api/books
{
  "books": [
    {
      "id": 1,
      "isbn": "978-0-7432-7356-5",
      "title": "The Great Gatsby",
      "author": "F. Scott Fitzgerald",
      "genre": "Fiction",
      "total_copies": 3,
      "available_copies": 3,
      "fine_rate": 0.20
    }
  ],
  "total": 10,
  "page": 1,
  "limit": 20
}

POST /api/loans  { "book_id": 1 }
{
  "loan_id": 7,
  "due_date": "2026-10-26T18:03:00.000Z"
}

PUT /api/loans/7/return
{
  "returned_at": "2026-10-12T18:04:00.000Z",
  "fine_amount": 0
}
```

## Key Takeaways

1. **CSRF protection matters for SPA + API setups.** Even when tokens live in JS memory (not cookies), forged requests from malicious pages can carry the user's cookies. The double-submit pattern ensures only pages that can read the CSRF value — i.e., same-origin pages — can make state-changing requests.
2. **JWTs are not sessions.** Access tokens cannot be revoked; that is why they are short-lived (15 min). Refresh tokens are stored server-side and can be explicitly revoked on logout, blocking long-term access after credential theft.
3. **RBAC in middleware, not in routes.** Putting access checks in a single middleware layer means a missed `if` in a route handler cannot open a privilege escalation hole.
4. **Parameterised queries eliminate SQL injection.** `db.prepare('SELECT * FROM users WHERE email = ?').get(email)` — the driver handles escaping; there is no way for user input to alter the query structure.
5. **Fine calculation stays server-side.** The client never submits a fine amount; the server recalculates from the due date on every return. Client-submitted financial values are always discarded.

## Further Reading

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
