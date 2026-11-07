# Threat model: AccessDesk

Scope: the API in this repository, run on one host with SQLite. Method: asset / actor / boundary / threat walk-through. This is a design review of a learning project, not a penetration test.

## Assets

| Asset | Why it matters |
|---|---|
| Access decisions (`access_requests.status`, `decided_by`) | The product's whole purpose; a forged approval grants real-world access |
| Credentials (`users.password_hash`) | Account takeover |
| JWT signing secret (`ACCESSDESK_JWT_SECRET`) | Whoever holds it can mint a token for anyone, including an admin |
| Roles (`users.role`) | Privilege level |
| Request contents (resource names, justifications) | Reveal what colleagues are trying to reach |
| Audit log | Accountability; must not be editable by ordinary users |

## Actors

Legitimate: employee, approver, admin. Adversarial: unauthenticated outsider; **curious or malicious employee** (the main case); a user with a stolen token; an approver abusing their role; someone with read access to the database file or the host.

## Trust boundaries

1. **Internet/client to API.** Everything in a request (headers, token, body, path, query) is untrusted.
2. **API to SQLite.** Queries are built only with bound parameters.
3. **Process to its environment.** The secret is read from env/`.env`; anyone who can read those is inside the boundary.
4. **Token to server state.** A token is a *claim of identity only*. Role, active flag and revocation are decided by server state on every request.

## Threats and mitigations

| # | Threat | Mitigation in this code | Test |
|---|---|---|---|
| 1 | Forged or edited token (change `sub`, change claims) | HS256 signature verified; `algorithms=["HS256"]` pinned; `alg=none` refused | tampered, other-secret, alg-none |
| 2 | Token meant for another service or issuer | `aud` and `iss` validated | wrong issuer, wrong audience |
| 3 | Replay of an old token | 15-minute `exp`; required claims `exp iat iss aud sub jti` | expired, missing-claim |
| 4 | Role claim inflation | Role is not in the token; read from DB per request | role-from-DB |
| 5 | Employee reads/edits a colleague's request by changing the ID (IDOR/BOLA) | Ownership check; foreign IDs return 404 identical to missing IDs | IDOR read/write, 404 parity |
| 6 | Employee performs approver/admin action | `require_permission` on every protected route | RBAC tests |
| 7 | Self-promotion or setting `status`/`requester_id` via payload (mass assignment) | `extra="forbid"` on every input model; register ignores roles; `requester_id` taken from token | payload tests |
| 8 | Approver approves own request; double approval race | Separation-of-duties check; `UPDATE ... WHERE status='pending'` | own-request, decided-twice |
| 9 | SQL injection | Parameterized queries only; typed path params; regex-limited `resource` | injection login, bad input |
| 10 | Password database theft | Argon2id hashes, never logged or returned | hash-format test |
| 11 | User enumeration / timing on login | Same 401 body; dummy-hash verification for unknown emails | identical-response test |
| 12 | Secrets in logs | Middleware logs method, path, status only; auth logs exception *type* | log-scan test |
| 13 | Leaked token still works after logout | `jti` denylist checked per request | logout test |
| 14 | Weak/missing signing secret | Startup fails if shorter than 32 chars; no default | (manual: start without `.env`) |

## Residual risks (not mitigated, deliberately)

- **Token theft:** a stolen token works until it expires (15 min) or the holder calls logout. There is no device binding, so a thief can act as the user meanwhile.
- **No rate limiting or lockout:** online password guessing and registration spam are possible. Argon2 cost slows it but does not stop it.
- **Open self-registration:** anyone who can reach the API can create an employee account.
- **Email enumeration via registration:** `409 Email already registered` confirms an address exists.
- **Shared symmetric secret (HS256):** any service that can verify tokens can also forge them. No key rotation.
- **Revocation list is in the same SQLite file;** single-node only.
- **No TLS in this repo:** tokens travel in clear text unless a reverse proxy terminates HTTPS.
- **Audit log is append-only by convention, not by database enforcement;** an attacker with DB access can edit it.
- **Approver collusion:** two approvers can approve each other's requests. Separation of duties stops self-approval only.
- **No MFA, password reset, or breached-password check.**
- **Swagger UI (`/docs`) is enabled.** Disable or protect it in any shared environment.
- **Dependencies are not pinned or scanned** (no lockfile, no `pip-audit`).

See [TOKENS_AND_DEPLOYMENT.md](TOKENS_AND_DEPLOYMENT.md) for what must change before internet exposure.
