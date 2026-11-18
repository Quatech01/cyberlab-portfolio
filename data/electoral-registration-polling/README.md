# Electoral Registration and Polling System

A secure full-stack UK electoral registration and polling portal demonstrating
JWT authentication, role-based access control, anonymous ballot casting, and
eight DevSecOps controls applied to a civic web application.

---

## What This Demonstrates

**Anonymous voting** is a cornerstone of democratic elections. This project shows
how to cast a ballot that prevents double-voting while making it technically
impossible to link a cast vote back to a specific voter.

The anonymisation technique: instead of storing the voter's ID alongside their
choice, the system computes `SHA-256(user_id + ":" + election_id + ":" + SALT)`.
The resulting hash is stored as the ballot record's voter identifier. A `UNIQUE`
constraint on `(election_id, voter_hash)` prevents the same person voting twice,
but the hash cannot be reversed — after the vote is cast the association between
voter and candidate is permanently destroyed.

The project also demonstrates:

- **UK electoral eligibility rules** — age 18+, British/Irish/Commonwealth
  nationality, exclusion of serving prisoners and convicted persons
- **Role separation** — voters, returning officers, and admins each see a
  different subset of the application
- **Full JWT auth cycle** — access tokens (15 min), refresh tokens (7 days,
  server-side revocable), and double-submit CSRF protection
- **Eight DevSecOps controls** in a single codebase

---

## How It Works

```
backend/           Express API — authentication, elections, voter registration, ballots
frontend/          Single-file SPA — login, dashboard, voting booth, results
tests/             node:test suite — 22 tests covering auth, RBAC, headers, business logic
backend/db/        node:sqlite DatabaseSync — zero native compilation needed
```

Three user roles exist in the system:

| Role               | Can do |
|--------------------|--------|
| `voter`            | Register to vote, browse elections, cast one ballot per open election |
| `returning_officer`| All voter actions + create elections, add candidates, open/close elections |
| `admin`            | All of the above + view all registered voters |

Ballots for a closed election are tallied publicly but neither the system nor
any user can determine who voted for which candidate.

---

## Quick Start

```bash
cd backend
npm install
node db/seed.js    # optional — creates demo accounts and elections

cd ../tests
npm install
npm test           # runs 22 tests against an in-memory database
```

To run the full application:

```bash
cd backend
npm start          # http://127.0.0.1:3000
```

Demo accounts created by seed.js:

| Email                  | Password      | Role               |
|------------------------|---------------|--------------------|
| admin@demo.local       | Admin1234!    | admin              |
| officer@demo.local     | Officer1234!  | returning_officer  |
| alice@demo.local       | Alice1234!    | voter (registered) |
| charlie@demo.local     | Charlie1234!  | voter (not registered) |

---

## Example Output

Election results endpoint `GET /api/elections/:id/results`:

```json
{
  "election": {
    "id": 1,
    "name": "Riverside Constituency General Election 2026",
    "constituency": "Riverside",
    "status": "closed"
  },
  "results": [
    { "id": 1, "name": "Sarah Obi",       "party": "Labour",           "votes": 1, "percentage": "50.0" },
    { "id": 2, "name": "James Whitfield", "party": "Conservative",     "votes": 1, "percentage": "50.0" },
    { "id": 3, "name": "Priya Patel",     "party": "Liberal Democrats","votes": 0, "percentage": "0.0"  }
  ],
  "total_votes": 2,
  "winner": { "name": "Sarah Obi", "party": "Labour", "votes": 1 }
}
```

---

## DevSecOps Controls

| Control              | Implementation |
|----------------------|---------------|
| Security headers     | Helmet — CSP, HSTS, X-Frame-Options: DENY, nosniff |
| CSRF protection      | Double-submit via JWT `csrf` claim + `X-CSRF-Token` header |
| Input validation     | express-validator on all routes; UK postcode regex |
| Rate limiting        | 20 req/15 min on auth; 100 req/min general; 5/min on vote |
| Parameterized queries| node:sqlite DatabaseSync — no string concatenation |
| Password hashing     | bcrypt cost 12 |
| JWT authentication   | HS256, 15-min access + 7-day revocable refresh |
| Role-based access    | `requireRole()` middleware, three roles |

---

## Key Takeaways

1. Anonymous voting does not require a trusted third party — a one-way hash
   combined with a database uniqueness constraint achieves both fraud prevention
   and voter privacy simultaneously.
2. JWT CSRF protection avoids server-side session state: embedding a random
   claim inside the signed token and reflecting it back as a header provides
   CSRF protection for a stateless API.
3. `node:sqlite` (DatabaseSync) is built into Node.js 22+ — no native
   compilation, no `node-gyp` failures, identical API to better-sqlite3.
4. Election status transitions (draft → open → closed) are one-way: a closed
   election cannot be reopened, protecting result integrity.

---

## Further Reading

- [Electoral Commission — How elections work in the UK](https://www.electoralcommission.org.uk/who-we-are-and-what-we-do/elections-and-referendums)
- [OWASP — Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
