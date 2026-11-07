"""Test fixtures.

Environment variables are set BEFORE the app is imported, so the tests never read your
real .env or touch your real database. The secret below is a throwaway, test-only value.
"""

import base64
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest

_TMP_DIR = tempfile.mkdtemp(prefix="accessdesk-tests-")
os.environ["ACCESSDESK_JWT_SECRET"] = "test-only-secret-" + "x" * 40
os.environ["ACCESSDESK_JWT_ISSUER"] = "accessdesk"
os.environ["ACCESSDESK_JWT_AUDIENCE"] = "accessdesk-api"
os.environ["ACCESSDESK_ACCESS_TOKEN_MINUTES"] = "15"
os.environ["ACCESSDESK_DATABASE_PATH"] = str(Path(_TMP_DIR) / "test.db")

from fastapi.testclient import TestClient  # noqa: E402

PASSWORD = "Test-only-password-123"


@pytest.fixture()
def client():
    Path(os.environ["ACCESSDESK_DATABASE_PATH"]).unlink(missing_ok=True)  # fresh DB per test
    from app.main import app

    with TestClient(app) as test_client:  # context manager runs the lifespan (creates tables)
        yield test_client


@pytest.fixture()
def make_user(client):
    """Insert a user directly in the DB (bypasses the API, so any role can be created)."""

    def _make(email: str, role: str = "employee") -> int:
        from app import db
        from app.security import hash_password

        conn = db.connect()
        try:
            user_id = db.create_user(conn, email, hash_password(PASSWORD), role)
            conn.commit()
        finally:
            conn.close()
        return user_id

    return _make


@pytest.fixture()
def login(client):
    def _login(email: str) -> dict[str, str]:
        resp = client.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _login


@pytest.fixture()
def forge():
    """Build tokens with chosen flaws so each validation check can be tested alone."""
    from app.config import get_settings

    def _forge(sub, *, secret: str | None = None, drop: tuple[str, ...] = (), **overrides) -> str:
        settings = get_settings()
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(sub),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": uuid.uuid4().hex,
        }
        claims.update(overrides)
        for name in drop:
            claims.pop(name)
        return jwt.encode(claims, secret or settings.jwt_secret, algorithm="HS256")

    return _forge


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.fixture()
def helpers():
    class H:
        b64url = staticmethod(b64url)
        b64url_decode = staticmethod(b64url_decode)
        dumps = staticmethod(lambda obj: json.dumps(obj).encode())
        loads = staticmethod(json.loads)

    return H
