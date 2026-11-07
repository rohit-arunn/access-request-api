# AccessDesk

A small FastAPI + SQLite API where employees request access to internal systems and approvers decide. It exists to demonstrate **authentication, role-based access control, object-level authorization, and secure input handling** in a codebase small enough to read in an hour.

**What this is:** a learning/portfolio project with first-party JWT authentication.
**What it is not:** production-ready, and **not OAuth2 or OpenID Connect** (see [docs/TOKENS_AND_DEPLOYMENT.md](docs/TOKENS_AND_DEPLOYMENT.md)).

## Why this project

| Idea considered | Verdict |
|---|---|
| Notes/todo API with admin and user roles | Roles are cosmetic; nothing meaningful to protect. Rejected. |
| Multi-tenant document store | Strong object-level auth story, but tenancy modeling eats the time budget. Rejected. |
| **Internal access-request and approval API** | **Chosen.** Different users genuinely need different powers, and there are real abuse cases: approving your own request, reading a colleague's justification, promoting yourself. |

- **Who uses it:** employees file requests ("read access to prod-db, because..."); approvers decide; admins manage roles and read the audit log.
- **Why auth is necessary:** approving access is itself a privileged act. Without authentication nobody knows who is asking; without authorization any employee could approve their own request.
- **Depth despite the size:** token validation (signature, algorithm pinning, issuer, audience, expiry, required claims), Argon2id hashing, DB-backed roles, ownership checks, separation of duties, atomic state transitions, mass-assignment protection, revocation on logout, audit log, and a test suite aimed at attacks rather than only happy paths.

## Architecture

```
Client -> POST /auth/login -> verify Argon2id hash -> sign JWT (sub, iss, aud, iat, exp, jti)
Client -> any route + "Authorization: Bearer <jwt>"
            |
            v
  deps.get_current_user   authentication: verify token, check revocation list,
            |             load user + role from DB (role is NOT in the token)
            v
  deps.require_permission authorization (RBAC): does this role grant the permission?
            |
            v
  router ownership check  authorization (object-level): may THIS user touch THIS row?
            |
            v
  parameterized SQL (sqlite3, "?" placeholders only)
```

```
app/config.py        settings from env/.env; refuses to start with a missing/short secret
app/permissions.py   Role, Permission, ROLE_PERMISSIONS (the one permissions table)
app/security.py      Argon2id hashing; JWT create/decode (algorithm pinned to HS256)
app/deps.py          get_current_user, require_permission
app/db.py            schema + helpers
app/schemas.py       input models (extra="forbid") and output models
app/routers/         auth.py, access_requests.py, admin.py
scripts/seed.py      demo users with random passwords -> demo_credentials.json (gitignored)
scripts/demo.py      five-minute demo / smoke test (standard library only)
tests/               pytest suite
docs/                threat model, tokens & deployment, demo, learning guide, interview notes
```

## Permissions

| Permission | employee | approver | admin |
|---|:-:|:-:|:-:|
| `request:create` (also edit/cancel **own** pending request) | yes | yes | yes |
| `request:read_own` | yes | yes | yes |
| `request:read_all` | no | yes | yes |
| `request:decide` (approve/reject) | no | yes | yes |
| `user:manage_roles` | no | no | yes |
| `audit:read` | no | no | yes |

Ownership rules sit **on top of** the table and apply to every role:
- Other people's requests return **404**, not 403, unless the role has `request:read_all`.
- Only the requester may edit or cancel a request (even admins cannot).
- Nobody may decide their own request; a request can be decided once.
- Admins cannot change their own role.

Authentication = *who are you* (JWT). Role = *what kind of user are you* (DB). Permission = *what may that role do* (table above). Ownership = *is this your record*.

## Setup (Windows PowerShell, Python 3.11+)

```powershell
cd access-request-api
py -3.11 -m venv .venv
# If activation is blocked:  Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

Copy-Item .env.example .env
$secret = python -c "import secrets; print(secrets.token_urlsafe(48))"
(Get-Content .env) -replace 'REPLACE_ME', $secret | Set-Content .env

python -m scripts.seed          # creates accessdesk.db and demo_credentials.json
uvicorn app.main:app --reload   # http://127.0.0.1:8000/docs
```

macOS/Linux: `python3 -m venv .venv && source .venv/bin/activate`, then the same `pip`/`python` commands; generate the secret with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` and paste it into `.env`.

`.env`, `*.db` and `demo_credentials.json` are gitignored. Demo passwords are random per machine and never printed or committed.

## Test and demo

```powershell
pytest -v                       # automated tests (use a throwaway DB and a test-only secret)
python scripts/demo.py          # with the server running and seeded; see docs/DEMO.md
```

In Swagger UI (`/docs`): call `POST /auth/login`, copy `access_token`, click **Authorize**, paste it.

## Verification status (read this before claiming anything)

- **Executed while building this:** `compileall` on all Python files; a scratch run of the real `app/security.py` against PyJWT (valid, expired, wrong issuer, wrong audience, other secret, wrong algorithm, each missing claim, tampered payload, `alg=none`, garbage: all rejected or accepted as intended); a scratch run of the real SQL schema and key queries on SQLite.
- **Generated but NOT executed:** the full `pytest` suite, `scripts/seed.py`, `scripts/demo.py`, and the FastAPI app itself. The build environment could not reach the Python package index, so FastAPI, Argon2 and pytest were never installed there.
- **Dependencies:** `requirements.txt` uses minimum versions, not a tested lockfile. After your first green run, `pip freeze > requirements.lock.txt`.
- **Docs consulted:** PyJWT usage docs (audience, issuer, required claims, expiry) and the OWASP Password Storage Cheat Sheet (Argon2id preferred; minimum m=19 MiB, t=2, p=1). I could **not** open the argon2-cffi docs; the claim that its defaults exceed the OWASP minimum is from memory, so check `PasswordHasher()` parameters yourself.

Run `pytest -v` first. If something fails, fix the code or the test before you describe the project to anyone.

## Out of scope on purpose

OAuth2/OIDC login via an identity provider, refresh tokens, rate limiting, account lockout, email verification, password reset, MFA, HTTPS termination, and a production database. Each is listed with its risk in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
