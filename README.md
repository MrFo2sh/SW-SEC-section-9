# DeadDrop // Access Control Lab

A deliberately vulnerable **REST API** for a university software-security course.
It teaches a chain: **Broken Authentication (OWASP A07) &rarr; Broken Access Control (OWASP A01)**.

Localhost only. Nothing here is safe to deploy.

---

## Mission

DeadDrop is a headless message-drop service. There is **no sign-up** and no UI to
click. The only way in is to **earn** a session by brute-forcing a weak account.
From that foothold, work your way up until you own the whole system.

Your objectives, in order:

1. **Foothold** — get a valid session token.
2. **Map the users** — enumerate accounts and read data you shouldn't.
3. **Escalate** — become an administrator.
4. **Own everything** — exercise admin-only powers across every account.

There are **four flags** (`FLAG{...}`). Each is returned by the API only when the
matching exploit actually works — they are proof of success, not hints.

---

## Running the lab

Requires Node.js 18+.

```bash
npm install
```

Two modes. The same code, toggled by the `SECURE` environment variable:

```bash
# VULNERABLE mode (default) — exploits work
node server.js

# SECURE mode — the same attacks are blocked
SECURE=1 node server.js
```

On Windows PowerShell:

```powershell
node server.js                      # vulnerable
$env:SECURE=1; node server.js       # secure
```

On Windows cmd.exe:

```cmd
node server.js
set SECURE=1 && node server.js
```

The server listens on **http://localhost:4000**. The top banner printed at startup
tells you which mode you are in. Do your attacks against vulnerable mode; then flip
to secure mode and confirm each one is now blocked.

Open http://localhost:4000/ in a browser for the landing page.

---

## Tools

This is a JSON API, so your usual web tools apply:

- **curl** — hand-craft single requests and read the JSON responses.
- **ffuf** — fuzz wordlists against an endpoint at speed.
- **Burp Suite** — intercept, repeat, and tamper with requests.

The whole lab is built to be **ffuf-friendly**: every outcome has a meaningful
HTTP **status code**, there are **no redirects**, and bodies are JSON. That means
the status code *is* the signal. Use ffuf's matchers/filters to separate hits from
misses:

- `-mc 200` — match only responses with status 200 (a success).
- `-mc 401` — match only 401s.
- `-fc 404` — filter out (hide) 404s.

Combine a wordlist (`-w`) with `FUZZ` placed anywhere in the URL or body.

---

## API reference

All endpoints return JSON. Authenticated endpoints expect an
`Authorization: Bearer <token>` header (no cookies).

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET  | `/` | no | Styled HTML landing page. |
| POST | `/api/login` | no | Exchange `{username, password}` for a `{token}`. |
| GET  | `/api/me` | yes | Return the caller's own account record. |
| GET  | `/api/users/:id` | yes | Look up a user account by id. |
| PATCH| `/api/account` | yes | Update the caller's own profile fields. |
| GET  | `/api/admin/users` | yes (admin) | List the full user roster. |
| POST | `/api/admin/users/:id/reset` | yes (admin) | Set a user's password (admin tool). |

### Status codes you will see

| Code | Meaning |
|------|---------|
| 200 | OK / success |
| 400 | Bad input |
| 401 | Not authenticated / bad credential |
| 403 | Forbidden (wrong role, or blocked in secure mode) |
| 404 | Not found |
| 429 | Rate-limited / locked (secure mode only) |

---

## Wordlists

Provided in this folder:

- `usernames.txt` — candidate account names.
- `passwords.txt` — common rockyou-style passwords.

One seeded account uses a long random password that is **not** in any wordlist.
You are not meant to crack it — you are meant to make cracking it irrelevant.

---

## What to hand in

Submit the **four flags**, each with **one line** explaining how you obtained it:

- `F1` — ...
- `F2` — ...
- `F3` — ...
- `F4` — ...

Then, in one or two sentences per vulnerability, describe what the fix in
**SECURE mode** does and why it stops your attack.
