"""Authentication tests: who is allowed in, and which tokens are refused."""

import logging
from datetime import datetime, timedelta, timezone

import jwt

from tests.conftest import PASSWORD

AUTH_PROTECTED = "/auth/me"


def jwt_encode_hs512(user_id, secret: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id), "iss": "accessdesk", "aud": "accessdesk-api",
        "iat": now, "exp": now + timedelta(minutes=5), "jti": "hs512-test",
    }
    return jwt.encode(claims, secret, algorithm="HS512")


def test_login_issues_short_lived_token(client, make_user):
    make_user("a@example.test")
    resp = client.post("/auth/login", json={"email": "a@example.test", "password": PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 15 * 60

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 15 * 60
    assert "role" not in claims  # roles are never trusted from the token


def test_wrong_password_and_unknown_user_look_identical(client, make_user):
    make_user("a@example.test")
    wrong_pw = client.post("/auth/login", json={"email": "a@example.test", "password": "nope-nope-nope"})
    unknown = client.post("/auth/login", json={"email": "ghost@example.test", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_sql_injection_in_login_is_just_a_failed_login(client, make_user):
    make_user("a@example.test")
    resp = client.post("/auth/login", json={"email": "' OR '1'='1", "password": "whatever-password"})
    assert resp.status_code == 401


def test_passwords_are_stored_as_argon2id_hashes(client, make_user):
    from app import db

    make_user("a@example.test")
    conn = db.connect()
    try:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    finally:
        conn.close()
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_missing_token_is_rejected(client):
    assert client.get(AUTH_PROTECTED).status_code == 401


def test_non_bearer_scheme_is_rejected(client):
    assert client.get(AUTH_PROTECTED, headers={"Authorization": "Basic abc123"}).status_code == 401


def test_garbage_token_is_rejected(client):
    assert client.get(AUTH_PROTECTED, headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_valid_token_is_accepted(client, make_user, forge):
    uid = make_user("a@example.test")
    resp = client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {forge(uid)}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "a@example.test"


def test_expired_token_is_rejected(client, make_user, forge):
    uid = make_user("a@example.test")
    now = datetime.now(timezone.utc)
    token = forge(uid, iat=now - timedelta(minutes=30), exp=now - timedelta(minutes=15))
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_tampered_payload_is_rejected(client, make_user, login, helpers):
    make_user("a@example.test")
    admin_id = make_user("admin@example.test", "admin")
    token = login("a@example.test")["Authorization"].split(" ")[1]

    header, payload, signature = token.split(".")
    claims = helpers.loads(helpers.b64url_decode(payload))
    claims["sub"] = str(admin_id)  # try to become the admin, keep the old signature
    forged_payload = helpers.b64url(helpers.dumps(claims))
    forged = f"{header}.{forged_payload}.{signature}"

    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_signed_with_another_secret_is_rejected(client, make_user, forge):
    uid = make_user("a@example.test")
    token = forge(uid, secret="a-completely-different-secret-" + "y" * 30)
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_alg_none_token_is_rejected(client, make_user, helpers):
    uid = make_user("a@example.test")
    now = int(datetime.now(timezone.utc).timestamp())
    header = helpers.b64url(helpers.dumps({"alg": "none", "typ": "JWT"}))
    payload = helpers.b64url(
        helpers.dumps(
            {"sub": str(uid), "iss": "accessdesk", "aud": "accessdesk-api",
             "iat": now, "exp": now + 300, "jti": "abc"}
        )
    )
    unsigned = f"{header}.{payload}."
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {unsigned}"}).status_code == 401


def test_token_signed_with_a_different_algorithm_is_rejected(client, make_user, forge):
    """Right secret, wrong algorithm (HS512 instead of HS256): only pinned algorithms are accepted."""
    uid = make_user("a@example.test")
    secret = "test-only-secret-" + "x" * 40
    token = jwt_encode_hs512(uid, secret)
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_wrong_issuer_is_rejected(client, make_user, forge):
    uid = make_user("a@example.test")
    token = forge(uid, iss="someone-else")
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_wrong_audience_is_rejected(client, make_user, forge):
    uid = make_user("a@example.test")
    token = forge(uid, aud="some-other-api")
    assert client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_missing_required_claim_is_rejected(client, make_user, forge):
    uid = make_user("a@example.test")
    for claim in ("exp", "jti", "aud", "iss", "sub", "iat"):
        token = forge(uid, drop=(claim,))
        resp = client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401, f"token without {claim} was accepted"


def test_logout_revokes_the_token(client, make_user, login):
    make_user("a@example.test")
    headers = login("a@example.test")
    assert client.get(AUTH_PROTECTED, headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get(AUTH_PROTECTED, headers=headers).status_code == 401


def test_deactivated_user_is_rejected_even_with_a_valid_token(client, make_user, login):
    from app import db

    uid = make_user("a@example.test")
    headers = login("a@example.test")
    conn = db.connect()
    try:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (uid,))
        conn.commit()
    finally:
        conn.close()
    assert client.get(AUTH_PROTECTED, headers=headers).status_code == 401

def test_register_creates_an_employee(client):
    resp = client.post("/auth/register", json={"email": "new@example.com", "password": "a-long-enough-password"})
    assert resp.status_code == 201
    assert resp.json()["role"] == "employee"

def test_register_rejects_a_role_in_the_payload(client):
    resp = client.post(
        "/auth/register",
        json={"email": "evil@example.com", "password": "a-long-enough-password", "role": "admin"},
    )
    assert resp.status_code == 422
    # and nothing was created
    assert client.post("/auth/login", json={"email": "evil@example.com", "password": "a-long-enough-password"}).status_code == 401


def test_register_rejects_short_passwords(client):
    resp = client.post("/auth/register", json={"email": "new@example.com", "password": "short"})
    assert resp.status_code == 422


def test_logs_contain_no_passwords_or_tokens(client, make_user, caplog):
    make_user("a@example.test")
    with caplog.at_level(logging.DEBUG):
        resp = client.post("/auth/login", json={"email": "a@example.test", "password": PASSWORD})
        token = resp.json()["access_token"]
        client.get(AUTH_PROTECTED, headers={"Authorization": f"Bearer {token}"})
        client.get(AUTH_PROTECTED, headers={"Authorization": "Bearer tampered." + token})
        client.post("/auth/login", json={"email": "a@example.test", "password": "wrong-password-value"})
    assert PASSWORD not in caplog.text
    assert token not in caplog.text
    assert "wrong-password-value" not in caplog.text
