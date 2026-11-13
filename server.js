// server.js — DeadDrop teaching lab (Broken Auth -> Broken Access Control)
//
// VULNERABLE by default:   node server.js
// FIXED (remediated):      SECURE=1 node server.js   (on Windows: set SECURE=1 && node server.js)
//
// Localhost-only university software-security lab. A real-looking web app (the
// pages under GET /, /login, /app, /account, /admin) sits on top of a JSON API.
// The UI only exposes the "intended" surface — it never shows admin controls to
// a regular user and never surfaces flags. The access-control bugs live in the
// API and are reachable only by bypassing the UI (curl / Burp / DevTools). That
// gap — a tidy UI over an API that forgets to enforce authorization — is the
// whole lesson.

const express = require('express');
const crypto = require('crypto');
const { FLAGS, seedUsers, buildSqlDb } = require('./db');

const SECURE = process.env.SECURE === '1';
const PORT = process.env.PORT || 4000;

const app = express();
app.use(express.json());

// ---- State (re-seeded on every start) ----------------------------------
let users = seedUsers();
const sessions = new Map();   // token   -> userId
const loginFails = new Map(); // username -> { count, lockUntil }
let sqlDB = null;             // sql.js SQLite DB, built at startup (admin search)

const LOCK_THRESHOLD = 5;        // fails before lockout (secure mode)
const LOCK_WINDOW_MS = 60 * 1000; // 60s lockout

function findByUsername(username) {
  return users.find((u) => u.username === username);
}
function findById(id) {
  return users.find((u) => u.id === id);
}
function publicUser(u) {
  // Never leak the password (and never the private drops of another user).
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
// Web UI (HTML pages). Thin client over the API: the browser holds the
// bearer token in localStorage and fetches data client-side.
// ========================================================================
app.get('/',        (req, res) => res.type('html').send(PAGE_LANDING));
app.get('/login',   (req, res) => res.type('html').send(PAGE_LOGIN));
app.get('/app',     (req, res) => res.type('html').send(PAGE_APP));
app.get('/account', (req, res) => res.type('html').send(PAGE_ACCOUNT));
app.get('/admin',   (req, res) => res.type('html').send(PAGE_ADMIN));

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
// GET /api/drops  (auth) -> the CALLER'S OWN notes only.
//   Correctly scoped (not vulnerable) — this is what the dashboard renders,
//   and a counter-example to the broken endpoints.
// ========================================================================
app.get('/api/drops', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  return res.status(200).json({ drops: user.drops || [] });
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

// ========================================================================
// GET /api/admin/search?q=  (auth, admin in BOTH modes) — member search.
//   VULNERABLE: q is concatenated straight into the SQL -> SQL injection.
//     Results are reflected in-band (great for UNION). A broken query (e.g.
//     a stray quote) is reflected ONLY by HTTP status 500 — no DB error text.
//   SECURE:     parameterized query; q is bound, never parsed as SQL.
// ========================================================================
app.get('/api/admin/search', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  const q = typeof req.query.q === 'string' ? req.query.q : '';

  if (SECURE) {
    try {
      const stmt = sqlDB.prepare(
        'SELECT id, username, display_name, email FROM users ' +
        "WHERE (username || ' ' || display_name) LIKE $q"
      );
      stmt.bind({ $q: '%' + q + '%' });
      const results = [];
      while (stmt.step()) results.push(stmt.getAsObject());
      stmt.free();
      return res.status(200).json({ results });
    } catch (e) {
      return res.status(400).json({ error: 'search failed' });
    }
  }

  // VULNERABLE: raw string concatenation -> classic SQLi.
  // Single injection point in a quoted string context: a lone `'` breaks the
  // query (-> 500), UNION/boolean payloads land cleanly.
  const sql =
    "SELECT id, username, display_name, email FROM users " +
    "WHERE (username || ' ' || display_name) LIKE '%" + q + "%'";
  try {
    const out = sqlDB.exec(sql);
    const results = out.length
      ? out[0].values.map((row) => {
          const o = {};
          out[0].columns.forEach((c, i) => { o[c] = row[i]; });
          return o;
        })
      : [];
    return res.status(200).json({ results });
  } catch (e) {
    // Reflect ONLY via the status code. No DB error text is returned.
    return res.status(500).json({ error: 'search failed' });
  }
});

// ---- Fallback 404 (JSON, no redirects) ---------------------------------
app.use((req, res) => {
  res.status(404).json({ error: 'not found' });
});

// ---- Startup: build the SQLite DB, then listen -------------------------
(async () => {
  sqlDB = await buildSqlDb();
  app.listen(PORT, () => {
    const mode = SECURE ? 'SECURE (fixed)' : 'VULNERABLE';
    console.log('========================================');
    console.log('  DeadDrop  //  mode: ' + mode);
    console.log('  http://localhost:' + PORT);
    console.log('  Toggle: SECURE=1 node server.js = FIXED');
    console.log('========================================');
  });
})();

// ========================================================================
// ---- Web UI templates (8-bit, light, projector-friendly) ---------------
// A believable product. No flags, no lab framing, no attack hints. Regular
// users never see admin controls; admin links/pages render only for admins.
// ========================================================================
const STYLE = `
  :root{--bg:#eef1e6;--panel:#ffffff;--ink:#15241a;--muted:#4b6b54;--accent:#15803d;--accent-bg:#dff3e4;--border:#15241a;--err:#b4231a}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:20px/1.45 "VT323",ui-monospace,Consolas,monospace}
  a{color:var(--accent);text-decoration:none}
  .brand{font:16px/1 "Press Start 2P",monospace;color:var(--accent);text-transform:uppercase;display:flex;align-items:center;gap:10px}
  .brand i{width:12px;height:12px;background:var(--accent);display:inline-block;box-shadow:inset -3px -3px 0 rgba(0,0,0,.25)}
  header{background:var(--panel);border-bottom:2px solid var(--border);position:sticky;top:0;z-index:10}
  header .bar{max-width:860px;margin:0 auto;padding:14px 20px;display:flex;align-items:center;gap:16px}
  nav{margin-left:auto;display:flex;gap:6px;align-items:center}
  nav a{font:9px/1 "Press Start 2P",monospace;text-transform:uppercase;color:var(--muted);padding:9px 10px;border:2px solid transparent}
  nav a:hover{color:var(--ink);border-color:var(--border)}
  main{max-width:860px;margin:0 auto;padding:28px 20px}
  h1{font:18px/1.4 "Press Start 2P",monospace;color:var(--ink);margin:0 0 10px}
  h2{font:12px/1.5 "Press Start 2P",monospace;color:var(--ink);margin:0 0 14px}
  .muted{color:var(--muted)}
  .panel{background:var(--panel);border:2px solid var(--border);box-shadow:5px 5px 0 var(--border);padding:24px;margin-bottom:20px}
  .card{background:var(--panel);border:2px solid var(--border);box-shadow:4px 4px 0 var(--border);padding:16px 18px;margin-bottom:14px}
  .card-t{font:11px/1.4 "Press Start 2P",monospace;color:var(--ink);margin-bottom:10px}
  .card-b{color:var(--muted)}
  label{display:block;font:9px/1 "Press Start 2P",monospace;color:var(--muted);text-transform:uppercase;margin:16px 0 6px}
  input{width:100%;padding:10px 12px;font:20px "VT323",ui-monospace,monospace;border:2px solid var(--border);background:var(--bg);color:var(--ink)}
  input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}
  button,.btn{margin-top:20px;display:inline-block;padding:12px 18px;font:10px/1 "Press Start 2P",monospace;text-transform:uppercase;border:2px solid var(--border);background:var(--accent);color:#fff;cursor:pointer;box-shadow:3px 3px 0 var(--border)}
  button:hover,.btn:hover{background:#0f6b31}
  button:active,.btn:active{transform:translate(1px,1px);box-shadow:2px 2px 0 var(--border)}
  table{width:100%;border-collapse:collapse;font-size:19px}
  th,td{text-align:left;padding:10px 10px;border-bottom:1px solid #cdd8cb}
  th{font:9px/1 "Press Start 2P",monospace;color:var(--muted);text-transform:uppercase}
  .note{margin-top:14px;font-size:18px;min-height:1.2em}
  .note.ok{color:var(--accent)} .note.err{color:var(--err)}
  .center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .auth{width:min(94vw,400px)}
  .boot{color:var(--muted);font-size:16px;margin-bottom:16px}
  @media (prefers-reduced-motion:reduce){*{animation:none!important}}
`;

const HEAD =
  '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<title>DeadDrop</title>' +
  '<link rel="preconnect" href="https://fonts.googleapis.com">' +
  '<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=VT323&display=swap" rel="stylesheet">' +
  '<style>' + STYLE + '</style>';

const HEADER =
  '<header><div class="bar"><a href="/app" class="brand"><i></i> DeadDrop</a><nav id="nav"></nav></div></header>';

// Shared client helpers: token handling, nav (admin link only for admins),
// and html-escaping. No flags are ever read or shown.
const BOOT = `
  function api(p,o){o=o||{};var t=localStorage.getItem('dd_token');o.headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(t){o.headers['Authorization']='Bearer '+t;}return fetch(p,o);}
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function logout(e){if(e){e.preventDefault();}localStorage.removeItem('dd_token');location.href='/login';}
  function renderNav(me){var n=document.getElementById('nav');if(!n){return;}var h='<a href="/app">Drops</a><a href="/account">Account</a>';if(me&&me.role==='admin'){h+='<a href="/admin">Admin</a>';}h+='<a href="#" id="logout">Sign out</a>';n.innerHTML=h;document.getElementById('logout').onclick=logout;}
  function boot(){var t=localStorage.getItem('dd_token');if(!t){location.href='/login';return Promise.resolve(null);}return api('/api/me').then(function(r){if(r.status===401){logout();return null;}return r.json();}).then(function(me){if(me){renderNav(me);}return me;});}
`;

function doc(inner, script) {
  return '<!doctype html><html lang="en"><head>' + HEAD + '</head><body>' + inner +
    '<script>' + BOOT + (script || '') + '</script></body></html>';
}

const PAGE_LANDING = doc(
  '<div class="center"><div class="panel" style="max-width:560px;text-align:center">' +
    '<div class="boot">DEADDROP OS 2.0 — READY</div>' +
    '<div class="brand" style="justify-content:center;font-size:22px;margin-bottom:16px"><i></i> DeadDrop</div>' +
    '<h1 style="font-size:16px">Private notes. Dead simple.</h1>' +
    '<p class="muted">Keep your drops in one place — synced, private, yours.</p>' +
    '<a class="btn" href="/login">Sign in</a>' +
  '</div></div>',
  "if(localStorage.getItem('dd_token')){location.href='/app';}"
);

const PAGE_LOGIN = doc(
  '<div class="center"><div class="panel auth">' +
    '<div class="brand" style="margin-bottom:18px"><i></i> DeadDrop</div>' +
    '<h2 style="margin-bottom:6px">Sign in</h2>' +
    '<p class="muted" style="font-size:17px;margin:0">Welcome back.</p>' +
    '<form id="f" autocomplete="off">' +
      '<label>Username</label><input name="username" autofocus required>' +
      '<label>Password</label><input name="password" type="password" required>' +
      '<button type="submit">Sign in</button>' +
      '<div class="note err" id="err"></div>' +
    '</form>' +
  '</div></div>',
  "if(localStorage.getItem('dd_token')){location.href='/app';}" +
  "var f=document.getElementById('f'),e=document.getElementById('err');" +
  "f.addEventListener('submit',function(ev){ev.preventDefault();e.textContent='';" +
  "fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.username.value.trim(),password:f.password.value})})" +
  ".then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})" +
  ".then(function(x){if(x.ok&&x.j&&x.j.token){localStorage.setItem('dd_token',x.j.token);location.href='/app';return;}e.textContent='Incorrect username or password.';})" +
  ".catch(function(){e.textContent='Something went wrong. Please try again.';});});"
);

const PAGE_APP = doc(
  HEADER +
  '<main>' +
    '<h1 id="hello">Your drops</h1>' +
    '<p class="muted">Your private notes, synced across devices.</p>' +
    '<div id="drops" style="margin-top:18px"></div>' +
  '</main>',
  "boot().then(function(me){if(!me){return;}" +
  "document.getElementById('hello').textContent='Welcome back, '+me.displayName;" +
  "api('/api/drops').then(function(r){return r.json();}).then(function(d){" +
  "var el=document.getElementById('drops');" +
  "if(!d.drops||!d.drops.length){el.innerHTML='<p class=\"muted\">No drops yet.</p>';return;}" +
  "el.innerHTML=d.drops.map(function(x){return '<div class=\"card\"><div class=\"card-t\">'+esc(x.title)+'</div><div class=\"card-b\">'+esc(x.body)+'</div></div>';}).join('');" +
  "});});"
);

const PAGE_ACCOUNT = doc(
  HEADER +
  '<main><div class="panel" style="max-width:520px">' +
    '<h2>Account settings</h2>' +
    '<p class="muted" id="whoami" style="font-size:17px;margin:0 0 4px"></p>' +
    '<form id="f" autocomplete="off">' +
      '<label>Display name</label><input name="displayName">' +
      '<label>Email</label><input name="email" type="email">' +
      '<button type="submit">Save changes</button>' +
      '<div class="note" id="msg"></div>' +
    '</form>' +
  '</div></main>',
  "boot().then(function(me){if(!me){return;}var f=document.getElementById('f');" +
  "f.displayName.value=me.displayName||'';f.email.value=me.email||'';" +
  "document.getElementById('whoami').textContent='@'+me.username;" +
  "f.addEventListener('submit',function(ev){ev.preventDefault();var m=document.getElementById('msg');m.textContent='';m.className='note';" +
  "api('/api/account',{method:'PATCH',body:JSON.stringify({displayName:f.displayName.value,email:f.email.value})})" +
  ".then(function(r){return r.json();}).then(function(){m.textContent='Saved.';m.className='note ok';})" +
  ".catch(function(){m.textContent='Could not save. Please try again.';m.className='note err';});});});"
);

const PAGE_ADMIN = doc(
  HEADER +
  '<main id="main">' +
    '<div class="panel">' +
      '<h2>Search members</h2>' +
      '<form id="sf" autocomplete="off" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">' +
        '<div style="flex:1;min-width:220px"><label>Find a member</label><input name="q" placeholder="name or username"></div>' +
        '<button type="submit" style="margin-top:0">Search</button>' +
      '</form>' +
      '<table style="margin-top:16px"><thead><tr><th>ID</th><th>Username</th><th>Name</th><th>Email</th></tr></thead>' +
      '<tbody id="sresults"></tbody></table>' +
    '</div>' +
    '<div class="panel">' +
      '<h2>Team members</h2>' +
      '<table><thead><tr><th>ID</th><th>Username</th><th>Name</th><th>Email</th><th>Role</th></tr></thead>' +
      '<tbody id="roster"></tbody></table>' +
    '</div>' +
  '</main>',
  "boot().then(function(me){if(!me){return;}" +
  "api('/api/admin/users').then(function(r){" +
  "if(r.status===403){document.getElementById('main').innerHTML='<div class=\"panel\"><h2>Access denied</h2><p class=\"muted\">You do not have permission to view this page.</p></div>';return null;}" +
  "return r.json();}).then(function(d){if(!d){return;}" +
  "document.getElementById('roster').innerHTML=d.users.map(function(u){return '<tr><td>'+u.id+'</td><td>'+esc(u.username)+'</td><td>'+esc(u.displayName)+'</td><td>'+esc(u.email)+'</td><td>'+esc(u.role)+'</td></tr>';}).join('');" +
  "var sf=document.getElementById('sf');if(sf){sf.addEventListener('submit',function(ev){ev.preventDefault();" +
  "api('/api/admin/search?q='+encodeURIComponent(sf.q.value)).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});}).then(function(x){" +
  "var tb=document.getElementById('sresults');" +
  "if(!x.ok||!x.j.results||!x.j.results.length){tb.innerHTML='<tr><td colspan=\"4\" class=\"muted\">No results.</td></tr>';return;}" +
  "tb.innerHTML=x.j.results.map(function(u){return '<tr><td>'+u.id+'</td><td>'+esc(u.username)+'</td><td>'+esc(u.display_name)+'</td><td>'+esc(u.email)+'</td></tr>';}).join('');" +
  "});});}" +
  "});});"
);
