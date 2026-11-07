"""First-party authentication: register, login, logout, whoami.

This is NOT OAuth2 or OpenID Connect. The API verifies passwords itself and issues its
own JWT access tokens. See README for what real OAuth2/OIDC would add.
"""

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Response, status

from .. import db as dbm
from ..config import get_settings
from ..deps import CurrentUser, get_current_user, now_unix
from ..permissions import Role
from ..schemas import LoginIn, RegisterIn, TokenOut, UserOut
from ..security import DUMMY_HASH, create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("accessdesk.auth")


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, conn: sqlite3.Connection = Depends(dbm.get_db)):
    # The role is NOT taken from the payload (RegisterIn forbids it). Self-registered
    # users are always plain employees; only an admin can change that later.
    try:
        user_id = dbm.create_user(
            conn, body.email, hash_password(body.password), Role.EMPLOYEE.value
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None
    dbm.audit(conn, user_id, "user.register", f"user:{user_id}")
    conn.commit()
    return UserOut(
        id=user_id, email=body.email.strip().lower(), role=Role.EMPLOYEE, is_active=True
    )


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, conn: sqlite3.Connection = Depends(dbm.get_db)):
    email = body.email.strip().lower()
    row = conn.execute(
        "SELECT id, password_hash, is_active FROM users WHERE email = ?", (email,)
    ).fetchone()

    # Always run one Argon2 verification, even for unknown emails (see DUMMY_HASH).
    password_ok = verify_password(row["password_hash"] if row else DUMMY_HASH, body.password)

    if row is None or not password_ok or not row["is_active"]:
        log.info("login failed")  # deliberately no email, no password
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")

    token, _jti, _exp = create_access_token(row["id"])
    dbm.audit(conn, row["id"], "auth.login", f"user:{row['id']}")
    conn.commit()
    return TokenOut(access_token=token, expires_in=get_settings().access_token_minutes * 60)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    user: CurrentUser = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    """Revoke the token used for THIS request by storing its jti until it would expire."""
    conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_unix(),))
    conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
        (user.token_jti, user.token_exp),
    )
    dbm.audit(conn, user.id, "auth.logout", f"user:{user.id}")
    conn.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser = Depends(get_current_user)):
    return UserOut(id=user.id, email=user.email, role=user.role, is_active=True)
