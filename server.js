// server.js — DeadDrop teaching lab (Broken Auth -> Broken Access Control)
//
// VULNERABLE by default:   node server.js
// FIXED (remediated):      SECURE=1 node server.js   (on Windows: set SECURE=1 && node server.js)
//
// Localhost-only university software-security lab. Pure JSON REST API plus
// one styled HTML landing page at GET /.

const express = require('express');
const crypto = require('crypto');
const { FLAGS, seedUsers } = require('./db');

const SECURE = process.env.SECURE === '1';
const PORT = process.env.PORT || 4000;

const app = express();
app.use(express.json());

// ---- State (re-seeded on every start) ----------------------------------
let users = seedUsers();
const sessions = new Map();   // token   -> userId
const loginFails = new Map(); // username -> { count, lockUntil }

const LOCK_THRESHOLD = 5;        // fails before lockout (secure mode)
const LOCK_WINDOW_MS = 60 * 1000; // 60s lockout

function findByUsername(username) {
  return users.find((u) => u.username === username);
}
function findById(id) {
  return users.find((u) => u.id === id);
}
function publicUser(u) {
  // Never leak the password.
  return { id: u.id, username: u.username, email: u.email, role: u.role, displayName: u.displayName };
}

// ---- Auth helper: Authorization: Bearer <token> -> user ----------------
function authUser(req) {
  const header = req.headers['authorization'] || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  const userId = sessions.get(token);
  if (userId == null) return null;
  return findById(userId) || null;
}

function requireAuth(req, res) {
  const user = authUser(req);
  if (!user) {
    res.status(401).json({ error: 'unauthenticated' });
    return null;
  }
  return user;
}

// ========================================================================
// GET /  — styled 8-bit landing page (no API logic)
// ========================================================================
app.get('/', (req, res) => {
  res.type('html').send(LANDING_HTML);
});

// ========================================================================
// POST /api/login  { username, password } -> { token }
// ========================================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password required' });
  }

  const user = findByUsername(username);

  if (SECURE) {
    // Lockout check first — even a correct password returns 429 while locked.
    const fail = loginFails.get(username);
    const now = Date.now();
    if (fail && fail.lockUntil && fail.lockUntil > now) {
      return res.status(429).json({ error: 'locked' });
    }
    // Generic failure for BOTH unknown user and wrong password (no enumeration).
    if (!user || user.password !== password) {
      const rec = loginFails.get(username) || { count: 0, lockUntil: 0 };
      rec.count += 1;
      if (rec.count >= LOCK_THRESHOLD) {
        rec.lockUntil = now + LOCK_WINDOW_MS;
        rec.count = 0;
      }
      loginFails.set(username, rec);
      return res.status(401).json({ error: 'invalid credentials' });
    }
    // Success — clear failures, issue token.
    loginFails.delete(username);
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, user.id);
    return res.status(200).json({ token });
  }

  // VULNERABLE: user enumeration + no rate limit.
  if (!user) {
    return res.status(404).json({ error: 'no such user' });
  }
  if (user.password !== password) {
    return res.status(401).json({ error: 'invalid password' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  return res.status(200).json({ token });
});

// ========================================================================
// GET /api/me  (auth) -> own record + F1 (proof of foothold)
// ========================================================================
app.get('/api/me', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  return res.status(200).json({ ...publicUser(user), flag: FLAGS.F1 });
});

// ========================================================================
// GET /api/users/:id  (auth)
//   VULNERABLE: IDOR read of any user; F2 when :id != your own id.
//   SECURE:     only self or admin; otherwise 403.
// ========================================================================
app.get('/api/users/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'invalid id' });
  }

  if (SECURE) {
    if (id !== user.id && user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    const target = findById(id);
    if (!target) return res.status(404).json({ error: 'not found' });
    return res.status(200).json(publicUser(target));
  }

  // VULNERABLE: return ANY user's record regardless of caller.
  const target = findById(id);
  if (!target) return res.status(404).json({ error: 'not found' });
  const body = publicUser(target);
  if (id !== user.id) body.flag = FLAGS.F2;
  return res.status(200).json(body);
});

// ========================================================================
// PATCH /api/account  (auth) — update YOUR OWN record (id from token).
//   VULNERABLE: mass assignment — blindly copies body incl. role; F3 on admin.
//   SECURE:     allow-list displayName + email only; role/id/password ignored.
// ========================================================================
app.patch('/api/account', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const body = req.body || {};
  if (typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'invalid body' });
  }

  if (SECURE) {
    // Allow-list ONLY safe fields. Never trust client for role/id/password.
    if (typeof body.displayName === 'string') user.displayName = body.displayName;
    if (typeof body.email === 'string') user.email = body.email;
    return res.status(200).json(publicUser(user));
  }

  // VULNERABLE: blind merge of client-supplied fields onto the user object,
  // including `role` -> privilege escalation. Keep id stable so the token
  // still resolves, but otherwise copy everything the client sent.
  for (const key of Object.keys(body)) {
    if (key === 'id') continue;
    user[key] = body[key];
  }
  const resp = publicUser(user);
  if (user.role === 'admin') resp.flag = FLAGS.F3;
  return res.status(200).json(resp);
});

// ========================================================================
// GET /api/admin/users  (auth, admin in BOTH modes) -> roster + F4
// ========================================================================
app.get('/api/admin/users', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  return res.status(200).json({ users: users.map(publicUser), flag: FLAGS.F4 });
});

// ========================================================================
// POST /api/admin/users/:id/reset  (auth, admin in BOTH modes) { password }
//   Legit admin power; blast-radius target once escalated.
// ========================================================================
app.post('/api/admin/users/:id/reset', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'invalid id' });
  }
  const { password } = req.body || {};
  if (typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'password required' });
  }

  const target = findById(id);
  if (!target) return res.status(404).json({ error: 'not found' });
  target.password = password;
  return res.status(200).json({ ok: true, id });
});

// ---- Fallback 404 (JSON, no redirects) ---------------------------------
app.use((req, res) => {
  res.status(404).json({ error: 'not found' });
});

app.listen(PORT, () => {
  const mode = SECURE ? 'SECURE (fixed)' : 'VULNERABLE';
  console.log('========================================');
  console.log('  DeadDrop API  //  mode: ' + mode);
  console.log('  http://localhost:' + PORT);
  console.log('  Toggle: SECURE=1 node server.js = FIXED');
  console.log('========================================');
});

// ---- Landing page HTML (8-bit, light, projector-friendly) --------------
const LANDING_HTML = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeadDrop // Access Control</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=VT323&display=swap" rel="stylesheet">
<style>
  :root{ --bg:#eef1e6; --panel:#ffffff; --ink:#15241a; --muted:#4b6b54; --accent:#15803d; --accent-bg:#dff3e4; --border:#15241a; --notice:#b45309; }
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:22px/1.4 "VT323",ui-monospace,Consolas,monospace;display:flex;align-items:center;justify-content:center;padding:24px}
  .panel{background:var(--panel);border:2px solid var(--border);box-shadow:6px 6px 0 var(--border);width:min(94vw,720px);padding:32px}
  .boot{color:var(--muted);font-size:18px;white-space:pre-line;margin-bottom:18px}
  h1{font:20px/1.5 "Press Start 2P",monospace;color:var(--accent);text-transform:uppercase;margin:0 0 4px;display:flex;align-items:center;gap:12px}
  h1 i{width:14px;height:14px;background:var(--accent);display:inline-block;box-shadow:inset -3px -3px 0 rgba(0,0,0,.25)}
  h1::after{content:"\\2588";animation:blink 1s steps(1) infinite;margin-left:-4px;color:var(--accent)}
  .tag{font:10px/1.6 "Press Start 2P",monospace;color:var(--muted);text-transform:uppercase;margin:0 0 20px}
  p{margin:0 0 14px;color:var(--ink)}
  .mono-accent{color:var(--accent)}
  .box{border:2px solid var(--border);padding:16px;margin:16px 0;background:var(--accent-bg)}
  .label{font:9px/1 "Press Start 2P",monospace;color:var(--muted);text-transform:uppercase;margin-bottom:8px}
  code{color:var(--notice)}
  .flags{display:flex;gap:10px;margin-top:8px}
  .flags span{font:9px/1 "Press Start 2P",monospace;border:2px solid var(--border);padding:8px 10px;color:var(--muted)}
  @keyframes blink{50%{opacity:0}}
  @media (prefers-reduced-motion:reduce){*{animation:none!important}}
</style></head>
<body>
  <div class="panel">
    <div class="boot">DEADDROP BIOS 2.0 ... PHOSPHOR OK
API ARMED ... ACCESS CONTROL: OFFLINE</div>
    <h1><i></i> DeadDrop</h1>
    <div class="tag">// broken access control &middot; rest api &middot; lab</div>
    <p>This is a headless REST API. There is <span class="mono-accent">no sign-up</span> and no UI to click &mdash; the only way in is to <span class="mono-accent">earn</span> a session.</p>
    <div class="box">
      <div class="label">Entry Point</div>
      <p style="margin:0">Authenticate at <code>POST /api/login</code>. Everything else lives under <code>/api</code>. Bring a wordlist.</p>
    </div>
    <p>Four flags. Get a foothold, map the users, climb to admin, and own the lot.</p>
    <div class="flags"><span>F1</span><span>F2</span><span>F3</span><span>F4</span></div>
  </div>
</body></html>`;
