# Learn it and own it

## The security-critical code in plain language

**`app/security.py: decode_access_token`**: this is the gate for every token. It calls PyJWT with four deliberate restrictions: only `HS256` is allowed (so an attacker cannot switch to `none` or another algorithm), the audience and issuer must match ours (so a token minted for some other service is useless here), expiry is checked, and six claims must be present (so a token with `exp` stripped out cannot live forever). Any failure raises, and the caller converts it into one generic 401.

**`app/security.py: create_access_token`**: the token holds *who* (`sub`) and housekeeping (`iss`, `aud`, `iat`, `exp`, `jti`), but not the role. That is a design decision: whatever is in a token cannot be changed until it expires, so power is looked up fresh from the database instead.

**`app/deps.py: get_current_user`**: authentication in four steps: decode the token; reject if its `jti` is in the revoked list; load the user from the database; reject if the user is missing or inactive. It returns a `CurrentUser` whose role came from the database. Every failure produces the *same* 401 text, so an attacker cannot tell "expired" from "revoked" from "forged". Logs record only the exception type.

**`app/deps.py: require_permission`**: a function that returns a dependency. `Depends(require_permission(Permission.REQUEST_DECIDE))` means "log in, and your role must contain this permission, else 403". The permission table lives in one place (`permissions.py`), so a role change is a one-line edit.

**`app/routers/access_requests.py: _fetch_visible / _fetch_owned`**: this is what stops IDOR. A role check says "employees may read requests"; it cannot say "only *your* requests". These helpers load the row and compare `requester_id` with the caller. Other people's rows return **404** (the same as a nonexistent ID), so probing IDs reveals nothing.

**`decide_request`**: three protections: you need `request:decide`; you cannot decide your own request; and the `UPDATE ... WHERE status = 'pending'` makes "check then change" a single atomic step, so two approvers cannot both win.

**`app/schemas.py: extra="forbid"`**: if a client sends fields we did not define (`role`, `status`, `requester_id`), validation fails with 422 rather than ignoring them. This closes mass assignment even if someone later wires a payload straight into a database update.

**`app/routers/auth.py: login`**: it runs one Argon2 verification even when the email does not exist (against a dummy hash), and returns the same message for both failures, so neither the response nor the timing reveals which emails are registered.

## Three exercises (about 10 minutes each)

**Exercise 1: change a permission and its test.** Give approvers the ability to read the audit log: add `Permission.AUDIT_READ` to `Role.APPROVER` in `permissions.py`. Run `pytest`. Which tests fail and why? Update `test_permissions_table_matches_documentation` and `test_approver_cannot_use_admin_endpoints` (the audit assertion) to match, then update the README table. *You are done when you can explain why one table edit changed behavior in several routes.*

**Exercise 2: add a new protected endpoint with ownership.** Add `GET /requests/{id}/history` that returns audit rows whose `target` is `request:{id}`. Only the requester and users with `request:read_all` may call it. Reuse `_fetch_visible` so the ownership rule is not rewritten. Write two tests: owner gets 200, a different employee gets 404. *Trap to notice:* where must the visibility check happen relative to the audit query?

**Exercise 3: break it on purpose.** Temporarily change `algorithms=[ALGORITHM]` in `decode_access_token` to `algorithms=["HS256", "HS512"]`, and separately delete `audience=` from the decode call. Run `pytest`. Expected: the different-algorithm test and the wrong-audience test turn red respectively. Confirm that, and say what attack each models. Restore the code. Then write one new test for a flaw the suite does *not* catch (suggestion: a token with `exp` in the future but `nbf` in the future must be rejected). *You are done when a deliberate bug turns a test red and you can say what attack that test models.*

## Checklist with honest timings

**Essential (about 90 min if installs and tests go smoothly):**
- [ ] Create venv, install requirements, create `.env` (10 min)
- [ ] `pytest -v`; fix anything that fails before moving on (10 to 30 min; this code has not yet been run end to end)
- [ ] Seed, start the server, click through Swagger once (10 min)
- [ ] `python scripts/demo.py` (5 min)
- [ ] Read `security.py`, `deps.py`, `access_requests.py` using this guide (20 min)
- [ ] Exercise 1 (10 min)

**Needed to really own it for interviews (another 1 to 2 hours):**
- [ ] Exercises 2 and 3
- [ ] Read `THREAT_MODEL.md` and `TOKENS_AND_DEPLOYMENT.md`; explain residual risks aloud without notes
- [ ] Rehearse `INTERVIEW.md`

**Optional improvements (do not start until the essentials are done):**
- Rate limiting on login; `pip freeze` lockfile; GitHub Actions running `pytest` and `pip-audit`; a `deactivate user` endpoint; replace first-party login with OAuth2/OIDC against a free identity-provider tier (a separate multi-hour project).

Stop adding features once the essential list is complete. A small project you can explain beats a larger one you cannot.
