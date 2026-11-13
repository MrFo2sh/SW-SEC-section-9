// db.js — in-memory seed data for the DeadDrop lab.
//
// TEACHING LAB NOTE: passwords are stored in PLAINTEXT on purpose.
// This is a deliberately vulnerable localhost-only teaching lab. A real
// application MUST store only salted password hashes (bcrypt/argon2) and
// never keep or return raw passwords. Do not copy this pattern.

const initSqlJs = require('sql.js');

// ---- Flags (proof-of-success constants) --------------------------------
const FLAGS = {
  F1: 'FLAG{auth_bruteforce_foothold}',       // foothold via brute force
  F2: 'FLAG{authz_idor_user_api}',            // IDOR read of other users
  F3: 'FLAG{authz_mass_assignment_privesc}',  // mass-assignment privilege escalation
  F4: 'FLAG{authz_admin_account_takeover}',   // reached admin-only functionality
  F5: 'FLAG{sqli_admin_search_db_dump}',      // SQL injection in the admin search
};

// ---- Fresh seed on every start -----------------------------------------
// Returns an array of user objects. Called at startup so each run is clean.
function seedUsers() {
  return [
    // id 1: strong password, NOT on any wordlist — never crackable by design.
    { id: 1, username: 'dd_admin', password: 'Zx9#Qv!m2_Lp7', role: 'admin',   email: 'admin@deaddrop.local',   displayName: 'Root',
      drops: [ { title: 'Platform keys', body: 'rotated the signing keys on the 1st. backups in the usual place.' },
               { title: 'Reminder', body: 'review the pending support escalations before Friday.' } ] },
    { id: 2, username: 'alice',    password: 'sunshine',      role: 'user',    email: 'alice@deaddrop.local',   displayName: 'Alice',
      drops: [ { title: 'Groceries', body: 'oat milk, tomatoes, coffee, dish soap' },
               { title: 'Standup', body: 'done: invoices. today: follow up with vendor.' } ] },
    { id: 3, username: 'bob',      password: 'qwerty',        role: 'user',    email: 'bob@deaddrop.local',     displayName: 'Bob',       // intended foothold
      drops: [ { title: 'Gym', body: 'mon/wed/fri — do not skip leg day again' },
               { title: 'Books', body: 'finish the Le Guin, start the PM one' } ] },
    { id: 4, username: 'charlie',  password: 'password1',     role: 'user',    email: 'charlie@deaddrop.local', displayName: 'Charlie',
      drops: [ { title: 'Trip', body: 'passport expires may — renew before booking' } ] },
    { id: 5, username: 'dave',     password: 'letmein',       role: 'user',    email: 'dave@deaddrop.local',    displayName: 'Dave',
      drops: [ { title: 'Recipes', body: 'the lentil soup needs more cumin next time' } ] },
    { id: 6, username: 'support',  password: 'monkey',        role: 'support', email: 'support@deaddrop.local', displayName: 'Support',
      drops: [ { title: 'Shift notes', body: 'quiet week on tickets, mostly password resets' } ] },
    { id: 7, username: 'erin',     password: 'dragon',        role: 'user',    email: 'erin@deaddrop.local',    displayName: 'Erin',
      drops: [ { title: 'Garden', body: 'water the tomatoes, repot the basil' } ] },
    { id: 8, username: 'frank',    password: 'football',      role: 'user',    email: 'frank@deaddrop.local',   displayName: 'Frank',
      drops: [ { title: 'Car', body: 'book the service, tyres need checking' } ] },
  ];
}

// ---- SQLite database (backs the admin search; SQLi target) -------------
// Built once at startup with sql.js (in-memory SQLite). Holds a `users` table
// WITH passwords (the dump payoff — including dd_admin's uncrackable one) and a
// `secrets` table that carries F5. Only reachable through the admin search.
async function buildSqlDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();
  db.run(
    'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT, display_name TEXT);' +
    'CREATE TABLE secrets (id INTEGER PRIMARY KEY, label TEXT, value TEXT);'
  );
  const insU = db.prepare('INSERT INTO users VALUES (?,?,?,?,?,?)');
  for (const u of seedUsers()) {
    insU.run([u.id, u.username, u.password, u.role, u.email, u.displayName]);
  }
  insU.free();
  const insS = db.prepare('INSERT INTO secrets VALUES (?,?,?)');
  insS.run([1, 'platform_signing_key', 'dd_live_sk_9f2a7c1e4b8d55']);
  insS.run([2, 'flag', FLAGS.F5]);
  insS.free();
  return db;
}

module.exports = { FLAGS, seedUsers, buildSqlDb };
