# Wards

**Session-based authentication built from primitives, with the attacks written as tests.**

No Passport, no Auth0, no NextAuth, no JWT library. Argon2 for hashing and `node:crypto` for everything else. The goal is to understand what those libraries do by doing it, and to end up with a repo that demonstrates that understanding.

---

## Status

Early. Nothing works yet. This document is the plan.

---

## Why build this

Auth is the thing everyone outsources and then gets asked about in interviews. Most tutorial implementations are quietly broken in the same three ways: they reuse the session ID across login, they leak account existence through response timing, and they rate limit on only one axis.

Wards implements the boring correct version of each, and proves it with tests that assert the *attack fails* rather than that the happy path works.

---

## What's in scope

- Registration and login with argon2id
- Server-side sessions in SQLite, opaque random IDs
- Session rotation on privilege change
- CSRF protection via double-submit tokens
- TOTP second factor, implemented from RFC 6238 directly
- Rate limiting per IP and per account
- Password change, 2FA enrollment, session listing and revocation

## What's deliberately out of scope

- OAuth and social login
- Email delivery (verification and reset tokens are printed to the console)
- A frontend framework — plain HTML forms, no build step
- Horizontal scaling concerns

---

## Project layout

```
wards/
├── src/
│   ├── server.js            # express app, mounts routes
│   ├── db/
│   │   ├── schema.sql
│   │   └── index.js         # better-sqlite3 connection
│   ├── auth/
│   │   ├── password.js      # argon2id hash, verify, rehash-on-login
│   │   ├── session.js       # create, validate, rotate, destroy
│   │   ├── csrf.js          # double-submit token
│   │   ├── totp.js          # RFC 6238 from node:crypto
│   │   └── ratelimit.js     # per-IP and per-account counters
│   ├── middleware/
│   │   ├── requireAuth.js
│   │   └── requireCsrf.js
│   └── routes/
│       ├── register.js
│       ├── login.js
│       └── account.js
├── test/
│   └── auth.test.js
├── public/                  # minimal HTML forms
└── package.json
```

---

## Schema

The design decisions live here, so it's worth getting right before writing any route handlers.

```sql
CREATE TABLE users (
  id             INTEGER PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,
  totp_secret    TEXT,               -- NULL until 2FA is enrolled
  totp_confirmed INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,       -- 32 random bytes, base64url
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT,
  user_agent TEXT
);

CREATE TABLE login_attempts (
  id          INTEGER PRIMARY KEY,
  key         TEXT NOT NULL,         -- "ip:1.2.3.4" or "user:42"
  attempted_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_attempts_key  ON login_attempts(key, attempted_at);
```

**Why a sessions table and not a JWT.** A JWT is valid until it expires; you cannot revoke it without keeping server-side state, at which point you have a sessions table with extra steps. Server-side sessions let you log someone out instantly, show them their active devices, and kill every session on password change. The tradeoff is a database read per request — cheap, and cheaper still with SQLite on one box.

Being able to explain that tradeoff is a large part of what this project is for.

---

## The three things that matter

### 1. Rotate the session ID on login

If the session ID a user carries before logging in is the same one they carry after, you have a **session fixation** vulnerability. An attacker plants a session ID they know, waits for the victim to authenticate with it, and inherits an authenticated session.

Destroy the pre-login session, create a new one, set the new cookie. Same on password change and on 2FA enrollment.

### 2. Make login timing constant

The naive handler returns early when the email isn't found — before doing any hashing. Argon2 is deliberately slow, so "no such user" comes back in a millisecond and "wrong password" takes a hundred. That gap is an account enumeration oracle.

Fix: always run a verify. If there's no user, verify against a dummy hash and discard the result.

```js
const user = db.getUserByEmail(email);
const hash = user?.password_hash ?? DUMMY_HASH;
const ok = await argon2.verify(hash, password);
if (!user || !ok) return genericError(res);
```

Return the identical error message and status either way.

### 3. Rate limit on two axes

Per-IP alone doesn't stop a botnet spraying one common password across many accounts from many addresses. Per-account alone lets one IP grind a password list against many accounts, and creates a griefing vector where an attacker locks out a victim on purpose.

Track both keys separately. Use exponential backoff rather than a hard lockout, so a legitimate user who fat-fingers their password gets in a few seconds later instead of being locked out for an hour.

---

## Cookie configuration

Five flags, and together they're the answer to most interview questions on this topic:

```js
res.cookie('sid', sessionId, {
  httpOnly: true,      // JS can't read it, so XSS can't exfiltrate it
  secure: true,        // HTTPS only
  sameSite: 'lax',     // blocks cross-site POST, allows top-level navigation
  maxAge: 1000 * 60 * 60 * 24 * 7,
  path: '/'
});
```

`sameSite: 'lax'` handles most CSRF on its own. The double-submit token stays in as defense in depth, and because implementing it is part of the point.

---

## TOTP from scratch

The whole algorithm is:

```
counter = floor(unix_seconds / 30)
hmac    = HMAC-SHA1(secret, counter_as_8_byte_big_endian)
offset  = hmac[19] & 0x0f
code    = (4 bytes at offset, high bit masked) % 1_000_000
```

About forty lines with `node:crypto`, and it produces a genuine "oh, that's all it is" moment. The secret is base32-encoded into an `otpauth://` URI, rendered as a QR code, and scanned by any authenticator app.

Details that matter:

- Accept a ±1 step window for clock drift. Not more — every extra step widens the guessing window.
- Store the secret unconfirmed until the user submits one valid code, then flip `totp_confirmed`. Otherwise a failed enrollment locks them out.
- Rate limit code verification too. Six digits is only a million possibilities.
- Generate single-use recovery codes at enrollment and hash them like passwords.

---

## Tests

The test file is the strongest part of the repo, because it reads as a list of attacks that don't work:

```
✓ session id changes after login          (fixation)
✓ login timing is constant for unknown accounts  (enumeration)
✓ sixth attempt from one ip is rejected   (spraying)
✓ sixth attempt on one account is rejected (credential stuffing)
✓ expired session returns 401
✓ session cookie is httpOnly and sameSite
✓ post without csrf token is rejected
✓ totp code from previous window is accepted
✓ totp code from three windows ago is rejected
✓ reused recovery code is rejected
✓ password change destroys all other sessions
```

`node:test` and `node:assert` are built in — no test framework dependency. For the timing test, sample both paths a few hundred times and assert the medians are within a small tolerance rather than comparing single runs.

---

## Roadmap

**v0.1** — schema, register, login, sessions, cookies
**v0.2** — CSRF, rate limiting, session rotation
**v0.3** — TOTP enrollment and verification, recovery codes
**v0.4** — account page: active sessions, revoke, change password
**v0.5** — the full attack test suite
**later** — WebAuthn/passkeys, argon2 parameter tuning writeup, brief comparison against how Passport handles the same problems

---

## Stack

Node 20+, Express, better-sqlite3, `argon2`, `qrcode`, `node:test`. Everything else from the standard library.

---

## Name

Wards are the ridges inside a lock that only the correct key can pass. It's the mechanism, not the metaphor — which fits a project about building the mechanism.

Backups: **Latchkey**, **Deadbolt**, **Doorman**, **Tumbler**.
