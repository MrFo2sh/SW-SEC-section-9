// db.js — in-memory seed data for the DeadDrop lab.
//
// TEACHING LAB NOTE: passwords are stored in PLAINTEXT on purpose.
// This is a deliberately vulnerable localhost-only teaching lab. A real
// application MUST store only salted password hashes (bcrypt/argon2) and
// never keep or return raw passwords. Do not copy this pattern.

// ---- Flags (proof-of-success constants) --------------------------------
const FLAGS = {
  F1: 'FLAG{auth_bruteforce_foothold}',       // foothold via brute force
  F2: 'FLAG{authz_idor_user_api}',            // IDOR read of other users
  F3: 'FLAG{authz_mass_assignment_privesc}',  // mass-assignment privilege escalation
  F4: 'FLAG{authz_admin_account_takeover}',   // reached admin-only functionality
};

// ---- Fresh seed on every start -----------------------------------------
// Returns an array of user objects. Called at startup so each run is clean.
function seedUsers() {
  return [
    // id 1: strong password, NOT on any wordlist — never crackable by design.
    { id: 1, username: 'dd_admin', password: 'Zx9#Qv!m2_Lp7', role: 'admin',   email: 'admin@deaddrop.local',   displayName: 'Root' },
    { id: 2, username: 'alice',    password: 'sunshine',      role: 'user',    email: 'alice@deaddrop.local',   displayName: 'Alice' },
    { id: 3, username: 'bob',      password: 'qwerty',        role: 'user',    email: 'bob@deaddrop.local',     displayName: 'Bob' },     // intended foothold
    { id: 4, username: 'charlie',  password: 'password1',     role: 'user',    email: 'charlie@deaddrop.local', displayName: 'Charlie' },
    { id: 5, username: 'dave',     password: 'letmein',       role: 'user',    email: 'dave@deaddrop.local',    displayName: 'Dave' },
    { id: 6, username: 'support',  password: 'monkey',        role: 'support', email: 'support@deaddrop.local', displayName: 'Support' },
    { id: 7, username: 'erin',     password: 'dragon',        role: 'user',    email: 'erin@deaddrop.local',    displayName: 'Erin' },
    { id: 8, username: 'frank',    password: 'football',      role: 'user',    email: 'frank@deaddrop.local',   displayName: 'Frank' },
  ];
}

module.exports = { FLAGS, seedUsers };
