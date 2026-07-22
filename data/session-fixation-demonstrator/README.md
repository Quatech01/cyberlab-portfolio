# Session Fixation Demonstrator

A hands-on tool that proves how session fixation attacks work and shows why regenerating session IDs after login is the essential defence.

## What This Demonstrates

**Session fixation** is an attack where an adversary plants a known session identifier in a victim's browser before the victim logs in. When the server fails to issue a new session ID upon authentication, the pre-authentication session is promoted to a privileged one — and the attacker, who already knows the session ID, gains full authenticated access without ever touching the victim's credentials.

The attack has three stages:

1. **Plant** — the attacker visits the target site, obtains a valid (unauthenticated) session ID, and delivers that ID to the victim via a crafted link or XSS snippet.
2. **Wait** — the victim clicks the link, carries the attacker's session ID, and logs in normally.
3. **Exploit** — because the vulnerable server skipped regenerating the session ID, the attacker's ID is now authenticated. The attacker sends requests with that same ID and receives the victim's data.

The defence is a single line of logic applied during every successful login: discard the pre-authentication session, create a brand-new one, and return it in the response cookie.

## How It Works

```
┌──────────────────┐          ┌────────────────────────────────┐
│   Demo Server    │          │       Scanner Tool             │
│  (FastAPI)       │          │       (tool/main.py)           │
│                  │          │                                │
│ GET  /session    │◄─────────│ 1. Obtain pre-auth session ID  │
│ POST /login/     │◄─────────│ 2. Authenticate with that ID   │
│      vulnerable  │          │ 3. Check: did session ID change?│
│                  │          │    NO → SESSION_FIXATION (HIGH)│
│ GET  /session    │◄─────────│ 4. Repeat with /login/safe     │
│ POST /login/safe │◄─────────│ 5. Check: did session ID change?│
│                  │          │    YES → no finding            │
└──────────────────┘          └────────────────────────────────┘
```

**`server/main.py`** — FastAPI demo server with:
- `GET /session` — issues a new `session_id` cookie if the caller has none
- `POST /login/vulnerable` — authenticates without regenerating the session ID (the flaw)
- `POST /login/safe` — invalidates the old session and issues a fresh one on login (the fix)
- `GET /profile` — returns user data only for authenticated sessions

**`tool/main.py`** — scanner that:
1. Opens a fresh HTTP session and requests a pre-auth session ID
2. Authenticates via `/login/vulnerable`, then compares the cookie before and after
3. Repeats for `/login/safe` using a separate client with a clean cookie jar
4. Emits structured JSON findings to stdout and a human-readable summary to stderr

**`tests/test.py`** — 25 pytest tests covering:
- Server health and session lifecycle
- The attacker-plants-session proof (victim logs in → attacker gets access)
- The safe endpoint proof (planted session rejected after login)
- Complete tool output format validation
- Unreachable server and invalid-credential edge cases

## Quick Start

```bash
# Install dependencies
cd server  && pip install -r requirements.txt && cd ..
cd tool    && pip install -r requirements.txt && cd ..
cd tests   && pip install -r requirements.txt && cd ..

# Run the demo server
cd server
python main.py          # Listening on http://127.0.0.1:3000

# In a second terminal, run the scanner
cd tool
python main.py --target http://localhost:3000

# Run the full test suite
cd tests
pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/login/vulnerable",
      "vulnerability_type": "SESSION_FIXATION",
      "evidence": "Session ID unchanged after successful login (id prefix: f3a9b21c…). An attacker who plants a known session ID before login gains authenticated access once the victim logs in.",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 1 session fixation issue(s). The vulnerable login endpoint does not regenerate the session ID after authentication, allowing an attacker to fix the session ID before login and gain access once the victim authenticates."
}
```

Stderr during a scan:

```
Scanning http://localhost:3000 for session fixation vulnerabilities...
[HIGH] SESSION_FIXATION @ /login/vulnerable
```

## Key Takeaways

- **Always regenerate the session ID after login.** The fix is not optional — omitting it turns every session into a potential fixation vector.
- **Invalidate the old session on the server side.** Issuing a new cookie while leaving the old session alive still lets an attacker reuse the planted ID.
- **Cookies alone don't fix this.** `HttpOnly` and `SameSite` are valuable but they prevent different attacks (XSS theft, CSRF). They do nothing to stop session fixation.
- **Scanners compare cookies before and after login.** Detection is straightforward: request `/session`, log in, check whether `Set-Cookie` returned a new, different ID.
- **OWASP Session Management guidelines mandate post-login regeneration** (SM-05) as a requirement for any application that uses cookie-based sessions.

## Further Reading

- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
