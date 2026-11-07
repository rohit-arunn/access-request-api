"""Reusable FastAPI dependencies. This is where authentication and RBAC are enforced.

Every protected route declares one of:
  * Depends(get_current_user)                  -> "must be logged in"
  * Depends(require_permission(Permission.X))  -> "must be logged in AND role grants X"
Object-level (ownership) checks happen in the routers because they need the record.
"""

import logging
import sqlite3
import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .db import get_db
from .permissions import ROLE_PERMISSIONS, Permission, Role
from .security import decode_access_token

log = logging.getLogger("accessdesk.auth")

# auto_error=False so WE control the response and keep it uniform.
bearer_scheme = HTTPBearer(auto_error=False, description="Paste the access_token from /auth/login")


@dataclass(frozen=True)
class CurrentUser:
    id: int
    email: str
    role: Role
    token_jti: str
    token_exp: int

    def can(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS[self.role]


def _unauthorized() -> HTTPException:
    # One message for every failure (missing, malformed, expired, tampered, revoked, ...)
    # so the response does not help an attacker learn which check failed.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db),
) -> CurrentUser:
    """Authentication: turn a bearer token into a trusted user, or raise 401."""
    if creds is None:
        raise _unauthorized()

    try:
        claims = decode_access_token(creds.credentials)
    except jwt.PyJWTError as exc:
        # Log only the exception TYPE, never the token.
        log.info("token rejected: %s", type(exc).__name__)
        raise _unauthorized() from None

    jti = claims["jti"]
    if conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone():
        log.info("token rejected: revoked")
        raise _unauthorized()

    try:
        user_id = int(claims["sub"])
    except ValueError:
        raise _unauthorized() from None

    row = conn.execute(
        "SELECT id, email, role, is_active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None or not row["is_active"]:
        log.info("token rejected: unknown or inactive user")
        raise _unauthorized()

    return CurrentUser(
        id=row["id"],
        email=row["email"],
        role=Role(row["role"]),  # role comes from the DB, never from the token
        token_jti=jti,
        token_exp=int(claims["exp"]),
    )


def require_permission(permission: Permission):
    """Authorization (RBAC): build a dependency that demands a specific permission."""

    def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not user.can(permission):
            log.info("permission denied: user_id=%s needs %s", user.id, permission.value)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


def now_unix() -> int:
    return int(time.time())
