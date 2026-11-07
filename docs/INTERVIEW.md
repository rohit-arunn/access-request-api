# Interview notes

## Resume bullets

Use these only after `pytest` passes on your machine, and adjust the wording to whatever you actually ran. Add no counts or percentages you did not measure.

- Built a FastAPI/SQLite access-request approval API with first-party JWT authentication (Argon2id password hashing; short-lived HS256 tokens validated for signature, algorithm, issuer, audience, expiry and required claims) and server-side role-based access control across three roles via reusable dependencies.
- Implemented object-level authorization and abuse defenses (owner-scoped records, separation of duties, mass-assignment-safe request schemas, logout revocation, audit log); wrote a pytest suite targeting forged/expired tokens, IDOR and privilege-escalation attempts, and a threat model documenting residual risks.

Do not say: "production-grade", "OAuth2", "secure", or anything about users or deployment. Accurate phrasing: "learning project", "first-party JWT auth", "OAuth2/OIDC integration is a documented next step".

## Two-minute walkthrough

1. **Problem.** Employees ask for access; approvers decide. The decision is the sensitive thing, so I needed to prove who is calling and what they may do.
2. **Login.** `POST /auth/login` verifies an Argon2id hash and returns a 15-minute JWT holding only identity and housekeeping claims.
3. **Every request.** `get_current_user` validates the token (pinned algorithm, issuer, audience, expiry, required claims), checks the revocation list, and loads the user and **role from the database**.
4. **RBAC.** `require_permission(...)` checks the role against one permissions table, else 403.
5. **Object-level.** Even with the right role, the handler checks whether this row is yours; if not, 404.
6. **Writes.** Input models forbid unknown fields, `requester_id` comes from the token, and state changes use `UPDATE ... WHERE status='pending'`.
7. **Evidence.** Tests model attacks: tampered, expired, wrong-audience and `alg=none` tokens; IDOR; self-promotion; self-approval.
8. **Honest limits.** No rate limiting, no TLS here, no OAuth2/OIDC, a stolen token works for up to 15 minutes. All listed in the threat model.

## Design choices and tradeoffs

| Choice | Why | Tradeoff |
|---|---|---|
| Role loaded from DB, not in the token | Demotions are immediate | One extra query per request |
| Short expiry, no refresh token | Small theft window, less code | Users re-login every 15 minutes |
| `jti` denylist for logout | Real revocation for a stateless token | Reintroduces server state; single-node SQLite |
| HS256 (shared secret) | Simple, one service | Any verifier can also forge; RS256/ES256 or an IdP is better for several services |
| 404 for foreign records | No ID enumeration | Slightly harder debugging for legitimate users |
| `extra="forbid"` everywhere | Mass assignment fails loudly | Clients sending harmless extra fields get 422 |
| Raw `sqlite3` with `?` | Transparent, no ORM to learn | Hand-written SQL; an ORM (SQLAlchemy) scales better |
| First-party auth | Fits the time budget | Owns password storage; not OAuth2/OIDC |

## Likely follow-up questions

- **"Is this OAuth2?"** No. JWT is a token format, OAuth2 is a delegation framework, OIDC adds identity on top. I issue my own JWTs; real integration would use an identity provider with Authorization Code + PKCE and validate its tokens via JWKS.
- **"Why not put the role in the JWT?"** It would be stale until expiry; a demoted admin would stay admin for up to 15 minutes.
- **"What does `alg=none` have to do with anything?"** Some libraries once trusted the token's own header; I pin the accepted algorithm list and there is a test.
- **"How would you revoke all of a user's tokens?"** Add a per-user `token_version` (or `tokens_valid_after` timestamp) claim checked against the DB, or deactivate the user, which already works.
- **"What if two approvers click at once?"** The conditional `UPDATE ... WHERE status='pending'` lets only one succeed; the other gets 409.
- **"Where could IDOR still hide?"** Any new endpoint that loads a row by ID without `_fetch_visible`/`_fetch_owned`. A good next step is a test that enumerates routes with path IDs.
- **"Why Argon2id?"** Memory-hard, OWASP's first recommendation. I used the library's defaults and did not tune them (and I did not verify those defaults against the argon2-cffi docs).
- **"What would you do first for production?"** TLS, rate limiting, an identity provider with MFA, secrets manager, Postgres, CI with dependency scanning (full list in `TOKENS_AND_DEPLOYMENT.md`).
- **"What's the weakest part?"** Open registration plus no rate limiting; and the project has had no independent review.
