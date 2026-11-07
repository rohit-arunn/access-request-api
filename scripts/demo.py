"""Five-minute demo: permitted actions and blocked attacks against a RUNNING server.

Standard library only. Prerequisites: server running, and `python -m scripts.seed` done.

    python scripts/demo.py                      # default http://127.0.0.1:8000
    python scripts/demo.py http://127.0.0.1:8000

Every step prints the expected HTTP status next to the actual one. Exit code is 1 if any
step differs, so this doubles as a smoke test.

NOTE: this script mutates the demo database (creates/approves requests, promotes bob,
logs alice out). Delete accessdesk.db + demo_credentials.json and reseed to run it again.
"""

import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
CREDS = json.loads(Path("demo_credentials.json").read_text(encoding="utf-8"))
failures = 0


def call(method: str, path: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, None


def step(title: str, expected: int, result: tuple):
    global failures
    status, payload = result
    ok = status == expected
    failures += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {title}\n       expected {expected}, got {status}")
    return payload


def login(email: str) -> str:
    status, payload = call("POST", "/auth/login", body={"email": email, "password": CREDS[email]["password"]})
    assert status == 200, f"login failed for {email}: {status}"
    return payload["access_token"]


def tamper(token: str) -> str:
    """Change the subject inside the payload but keep the old signature."""
    header, payload, signature = token.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["sub"] = "4"  # try to become user 4 (the admin)
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


print("== Permitted actions ==")
alice = login("alice@example.test")
bob = login("bob@example.test")
carol = login("carol@example.test")
dave = login("dave@example.test")

created = step(
    "alice (employee) creates her own request", 201,
    call("POST", "/requests", alice, {"resource": "staging-db:read", "justification": "Reproducing bug 1432 on staging."}),
)
alice_request = created["id"]
step("alice reads her own request", 200, call("GET", f"/requests/{alice_request}", alice))
step("carol (approver) lists ALL requests", 200, call("GET", "/requests?scope=all", carol))
step(
    "carol approves alice's request", 200,
    call("POST", f"/requests/{alice_request}/decision", carol, {"decision": "approve", "note": "Time-boxed, OK."}),
)

print("\n== Blocked attacks ==")
step("bob reads alice's request by changing the ID (IDOR)", 404, call("GET", f"/requests/{alice_request}", bob))
step(
    "bob edits alice's request (IDOR write)", 404,
    call("PATCH", f"/requests/{alice_request}", bob, {"justification": "I am rewriting your request."}),
)
step("alice (employee) lists ALL requests", 403, call("GET", "/requests?scope=all", alice))
step("alice tries to approve a request", 403, call("POST", "/requests/1/decision", alice, {"decision": "approve"}))
step("alice promotes herself via the admin endpoint", 403, call("PUT", "/admin/users/1/role", alice, {"role": "admin"}))
step(
    "alice registers a new user with role=admin in the payload", 422,
    call("POST", "/auth/register", None, {"email": "mallory@example.test", "password": "a-long-enough-password", "role": "admin"}),
)
step(
    "alice sets status=approved on her own request", 422,
    call("PATCH", "/requests/1", alice, {"justification": "Please approve this one.", "status": "approved"}),
)
own = step(
    "carol creates a request, then tries to approve it herself", 201,
    call("POST", "/requests", carol, {"resource": "prod-db:write", "justification": "Hotfix for the migration."}),
)
step("  ... separation of duties blocks it", 403, call("POST", f"/requests/{own['id']}/decision", carol, {"decision": "approve"}))
step("request with no token", 401, call("GET", "/auth/me"))
step("request with a tampered token", 401, call("GET", "/auth/me", tamper(alice)))

print("\n== Role changes and logout ==")
step("dave (admin) promotes bob to approver", 200, call("PUT", "/admin/users/2/role", dave, {"role": "approver"}))
step("bob's EXISTING token now works as approver (role is read from the DB)", 200, call("GET", "/requests?scope=all", bob))
step("alice logs out", 204, call("POST", "/auth/logout", alice))
step("alice's old token is rejected after logout", 401, call("GET", "/auth/me", alice))
step("dave reads the audit log", 200, call("GET", "/admin/audit", dave))

print(f"\n{'ALL STEPS MATCHED' if failures == 0 else str(failures) + ' STEP(S) DIFFERED'}")
sys.exit(1 if failures else 0)
