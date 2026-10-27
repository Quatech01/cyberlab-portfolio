# Timetable and Room Scheduling System

A secure full-stack web application for managing school timetables — built to demonstrate the full DevSecOps stack in a realistic UK school context.

---

## What This Demonstrates

UK secondary schools schedule hundreds of lessons every week across dozens of rooms and teachers. This project shows how to build a production-grade scheduling system with:

- **Clash detection** at the API level: the server rejects any timetable entry where the teacher or room is already occupied in that time slot, preventing double-bookings before they reach the database
- **Role-based access control** with three tiers: admins build and manage the timetable, teachers view their own schedule, students view their group's schedule
- **JWT authentication** with short-lived access tokens (15 min), long-lived refresh tokens (7 days), and server-side revocation
- **CSRF protection** using a per-session token returned on login and validated on every state-changing request
- **Input validation** on all API boundaries using express-validator, with parameterized SQLite queries throughout
- **Security headers** via Helmet (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- **Audit logging** of every timetable change, including who made it and when

---

## How It Works

```
frontend/index.html     — Self-contained SPA (login, admin builder, teacher/student views)
backend/index.js        — Express app with all middleware wired up
backend/routes/         — Auth, rooms, subjects, teachers, groups, timeslots, timetable
backend/middleware/     — JWT auth + requireRole, CSRF token validation
backend/db/             — node:sqlite DatabaseSync schema + auto-seeded time slots
tests/test.js           — 22 node:test tests gating the GitHub push
```

The timetable grid is 5 days × 5 periods (standard UK school day: 08:50–14:30 with break and lunch). Before inserting an entry, the API checks three clash conditions:
1. Same **teacher** in the same time slot → 409 `clash_type: teacher`
2. Same **room** in the same time slot → 409 `clash_type: room`
3. Same **student group** in the same time slot → 409 `clash_type: group`

The frontend admin view renders the full weekly grid. Teachers see only their own periods. Students select their form group and see only that group's lessons.

---

## Quick Start

**Prerequisites:** Node.js 24+

```bash
# Install backend dependencies
cd backend && npm install

# Seed demo data (optional)
node db/seed.js

# Start the server
node index.js
# → http://127.0.0.1:3000

# Run tests
cd ../tests && npm install && npm test
```

Demo admin login after seeding: `headteacher@meadowside.edu` / `Admin@Meadow24`

---

## Example Output

`GET /api/timetable` (admin):

```json
[
  {
    "id": 1,
    "teacher_id": 1,
    "teacher_name": "Jane Smith",
    "department": "Mathematics",
    "room_id": 1,
    "room_name": "Room 101",
    "building": "Main Block",
    "subject_name": "Mathematics",
    "subject_code": "MA",
    "group_name": "9A",
    "year_group": 9,
    "day_of_week": 1,
    "period_number": 1,
    "start_time": "08:50",
    "end_time": "09:40"
  }
]
```

Teacher clash response:

```json
{
  "error": "Teacher is already scheduled in this time slot",
  "clash_type": "teacher"
}
```

---

## Key Takeaways

1. **Clash detection belongs on the server**, not the client — the frontend grid is a convenience, but a race condition or direct API call could bypass any client-side guard
2. **JWT access tokens should be short-lived** — 15 minutes limits the damage window if a token is intercepted; refresh tokens stored server-side can be revoked immediately
3. **CSRF tokens protect authenticated sessions** — even if an attacker can execute JavaScript in another tab, they cannot forge the per-session CSRF token
4. **Parameterized queries eliminate SQL injection** — the room name `'; DROP TABLE rooms; --` is stored literally as a string, not executed as SQL
5. **RBAC must be enforced in middleware** — inline role checks inside route handlers are easy to forget; a requireRole() middleware applied to the route array is harder to skip accidentally

---

## Further Reading

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
