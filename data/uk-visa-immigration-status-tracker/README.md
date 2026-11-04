# UK Visa and Immigration Status Tracker

A full-stack web application for tracking UK visa applications, document checklists, and key immigration deadlines. Built to demonstrate secure authentication, role-based access control, and DevSecOps practices in a realistic UK Home Office context.

## What This Demonstrates

Immigration case management involves some of the most sensitive personal data a system can hold: passport numbers, BRP details, biometric records, and right-to-remain status. This project shows how to build a system where:

- Applicants can only see their own cases
- Immigration advisers can manage client portfolios but cannot cross-contaminate case data
- Admins have full visibility but are still subject to CSRF and audit controls
- Passport numbers are masked at rest — only the last four digits are ever stored
- Visa expiry alerts fire 28 days before the grace period, mirroring the Home Office's own guidance

## How It Works

```
backend/          Express API, JWT auth, SQLite via node:sqlite
  routes/         /api/auth and /api/applications
  middleware/     Auth (JWT + bcrypt), CSRF, audit logging
  db/             schema.sql, init.js (node:sqlite), seed.js
frontend/         Self-contained SPA (index.html, all CSS/JS inline)
tests/            34 node:test cases covering all 6 test groups
```

The server starts on port 3000, seeds five demo accounts (admin, adviser, three applicants), and three pre-built visa applications. The frontend is a hash-routing SPA that keeps the access token in memory — never in localStorage.

## Quick Start

```bash
# Install and start the backend
cd backend && npm install && node index.js

# Open the frontend
# Navigate to http://127.0.0.1:3000

# Run tests
cd tests && node --test --test-concurrency=1 test.js
```

**Demo accounts:**

| Email | Password | Role |
|---|---|---|
| admin@visalab.dev | Admin@2024! | admin |
| sarah@visalab.dev | Adviser@2024! | adviser |
| john@example.com | User1@2024! | applicant |
| priya@example.com | User2@2024! | applicant |
| wei@example.com | User3@2024! | applicant |

## Example Output

GET `/api/applications/1` (as john, the applicant):

```json
{
  "id": 1,
  "reference_number": "GWF0001234",
  "visa_type": "Skilled Worker",
  "applicant_name": "John Smith",
  "nationality": "American",
  "passport_number_masked": "****5678",
  "stage": "approved",
  "visa_expiry_date": "2031-05-01T00:00:00.000Z",
  "days_until_expiry": 1643,
  "ilr_eligibility_date": "2030-05-01T00:00:00.000Z",
  "alert_28_day": false,
  "documents": [...],
  "status_history": [
    { "stage": "submitted", "notes": "Application received online" },
    { "stage": "biometrics", "notes": "Biometrics appointment completed" },
    { "stage": "decision_pending", "notes": "Under consideration" },
    { "stage": "approved",  "notes": "Visa granted — BRP to follow by post" }
  ]
}
```

## Key Takeaways

- **Passport masking**: only the last four digits of a passport number are stored (`****5678`). The raw number is never persisted, only the masked form.
- **CSRF double-submit pattern**: a CSRF token is issued at login and must accompany every state-changing request. Requests without it are rejected with HTTP 403 before any business logic runs.
- **Role enforcement in middleware**: `requireRole('admin','adviser')` is a middleware factory — the check happens in one place, not scattered across routes.
- **ILR and citizenship eligibility dates**: calculated server-side from the visa approval date using UK Immigration Rules (5 years continuous residence for ILR, 6 for citizenship on most routes).
- **28-day expiry alert**: mirrors the Home Office grace period — applicants are alerted when their visa expires in ≤ 28 days so they can apply for an extension or switch route in time.
- **Audit log**: every read and write is logged with the user ID, action, resource type, and IP address. This satisfies UK GDPR Article 30 record-keeping requirements.

## Further Reading

- [UK Visas and Immigration — visa categories](https://www.gov.uk/browse/visas-immigration)
- [Home Office — right to remain and ILR](https://www.gov.uk/indefinite-leave-to-remain)
- [OWASP — Broken Access Control (Top 10 A01)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP — CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
