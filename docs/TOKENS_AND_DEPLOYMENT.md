# Tokens, revocation, OAuth2 vs OIDC vs JWT, and going to production

## OAuth2, OpenID Connect and JWT are different things

- **JWT** is a *token format*: signed JSON (header.payload.signature). It says nothing about how a token is obtained or what it means. This project uses JWTs as access tokens.
- **OAuth2** is an *authorization framework*: how a client obtains limited access to an API on a user's behalf from an authorization server (flows such as Authorization Code with PKCE). It defines grants, scopes and redirects. Access tokens may be JWTs or opaque strings.
- **OpenID Connect (OIDC)** is an *identity layer on top of OAuth2*: it adds an ID token (a JWT about who logged in), standard claims and discovery, so an app can say "log in with an identity provider".

**What this project is:** first-party authentication. It checks passwords itself and signs its own JWTs. It uses FastAPI's `HTTPBearer` helper only to read the `Authorization` header. There is no authorization server, no redirect flow, no PKCE, no scopes, no refresh tokens and no ID tokens, so **it is not an OAuth2 or OIDC implementation**, and the OAuth2 integration is outside the completed scope.

**What the integration would look like:** register the API and a client with an established identity provider (Auth0, Microsoft Entra ID, Google, Keycloak, ...); the client uses Authorization Code with PKCE; this API stops handling passwords and instead validates the provider's tokens against its published keys (JWKS, usually RS256/ES256), checking `iss`, `aud` and `exp`. Users and roles could still be mapped locally by the provider's stable `sub`. The deprecated resource-owner password grant should not be used.

## Token lifecycle in this project

| Question | Behavior |
|---|---|
| What is in the token? | `sub` (user id), `iss`, `aud`, `iat`, `exp`, `jti`. No role, no email. |
| How long does it live? | 15 minutes (`ACCESSDESK_ACCESS_TOKEN_MINUTES`, capped at 60). No refresh token: users log in again. |
| What if a token is stolen? | It works until it expires or is revoked. Bearer tokens are possession-based; there is no client binding. The 15-minute lifetime limits the window. |
| Logout | `POST /auth/logout` stores the token's `jti` in `revoked_tokens` until its `exp`; every request checks that table. Only the presented token is revoked; other tokens for the same user stay valid. |
| Admin demotes a user | Takes effect on the next request, because the role is read from the DB. |
| Account deactivated (`is_active = 0`) | Rejected on the next request. There is no endpoint for this; it is a DB-level lever. |
| Secret rotated | All existing tokens become invalid at once. There is no overlap/rotation scheme. |

If a user suspects theft today: log out (kills that token), and an admin would have to deactivate the account in the database to cut off other tokens.

## Before internet deployment

Must change:
1. **HTTPS everywhere** (reverse proxy or platform TLS), HSTS, and never put tokens in URLs.
2. **Rate limiting and lockout/backoff** on `/auth/login` and `/auth/register`; consider closing open registration.
3. **Secrets management:** a secrets manager instead of `.env`; a rotation plan; consider asymmetric signing (RS256/ES256) or an external identity provider so API instances only hold a public key.
4. **Real identity:** OAuth2/OIDC with an identity provider, MFA, and no local password storage if possible.
5. **Database:** PostgreSQL (or similar) with migrations, least-privilege DB user, backups; an append-only or externally shipped audit log; a shared revocation store (database or Redis) if running more than one instance.
6. **Operational hardening:** disable `/docs` or protect it, restrict CORS to known origins (no browser client exists here, so none is configured), security headers, request-size limits, structured logging with alerting on repeated 401/403.
7. **Supply chain:** pinned lockfile, `pip-audit` or equivalent in CI, container image scanning.
8. **Refresh tokens** (rotating, stored hashed) if sessions longer than 15 minutes are required, plus session listing and "log out everywhere".
9. **Independent security review and load/abuse testing.** This repository has had neither.
