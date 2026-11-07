# Five-minute demo

**Status:** `scripts/demo.py` was written to match the code but has **not been run** against a live server (see README, Verification status). Run it once yourself before presenting, and treat any mismatch as a bug to fix, not to hide.

## Setup (once)

Server running and database seeded (README Setup). The seed creates users in this order, which the demo relies on: alice (id 1, employee), bob (2, employee), carol (3, approver), dave (4, admin). The demo **changes the database** (promotes bob, logs alice out), so to run it again: stop the server, delete `accessdesk.db` and `demo_credentials.json`, then reseed.

## Fast path: automated

```powershell
python scripts/demo.py
```

Each line prints `PASS`/`FAIL` with expected and actual status. Exit code 1 if anything differs.

## What it shows

| Step | Action | Expected | What it proves |
|---|---|---|---|
| 1 | alice creates a request | 201 | Employees can file requests |
| 2 | alice reads it | 200 | Owners can read their own records |
| 3 | carol lists all requests | 200 | Approvers have `request:read_all` |
| 4 | carol approves alice's request | 200 | Approvers have `request:decide` |
| 5 | bob GETs alice's request ID | **404** | Object-level authorization (IDOR blocked) |
| 6 | bob PATCHes alice's request | **404** | Same, for writes |
| 7 | alice lists `scope=all` | **403** | RBAC: employees lack `read_all` |
| 8 | alice POSTs a decision | **403** | RBAC: employees cannot approve |
| 9 | alice PUTs her own role to admin | **403** | No self-promotion |
| 10 | register with `"role":"admin"` in the body | **422** | Mass assignment rejected |
| 11 | PATCH with `"status":"approved"` | **422** | Sensitive fields cannot be set by the owner |
| 12 | carol approves her own request | **403** | Separation of duties |
| 13 | no token / tampered token | **401** / **401** | Authentication |
| 14 | dave promotes bob; bob's old token now lists all | 200 / 200 | Roles are read from the DB, not the token |
| 15 | alice logs out, reuses her token | 204 / **401** | Revocation |
| 16 | dave reads the audit log | 200 | Admin-only visibility |

## Manual path in Swagger UI (`/docs`) — about 3 minutes

1. `POST /auth/login` as `alice@example.test` (password in `demo_credentials.json`). Copy `access_token`. Click **Authorize**, paste it.
2. `GET /auth/me`: role `employee`.
3. `GET /requests?scope=all`: **403**.
4. `PUT /admin/users/1/role` with `{"role":"admin"}`: **403**.
5. Click **Authorize** again, log out, and paste a token from `bob@example.test`. `GET /requests/1` (alice's): **404**.
6. Log in as `carol@example.test`, authorize, `GET /requests?scope=all`: **200**; `POST /requests/1/decision` with `{"decision":"approve"}`: **200**.
7. `POST /auth/logout`, then `GET /auth/me` with the same token: **401**.

## PowerShell one-liners (optional)

```powershell
$creds = Get-Content demo_credentials.json | ConvertFrom-Json
$body  = @{ email = "alice@example.test"; password = $creds."alice@example.test".password } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType "application/json" -Body $body).access_token
Invoke-RestMethod -Uri http://127.0.0.1:8000/auth/me -Headers @{ Authorization = "Bearer $token" }
```

Blocked requests surface as PowerShell errors (e.g. "403 Forbidden"); that is the expected outcome.
