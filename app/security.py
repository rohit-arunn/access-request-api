"""Password hashing and JWT access tokens.

No cryptography is implemented here: Argon2 comes from argon2-cffi and JWT signing and
validation come from PyJWT. This file only decides *how* they are called.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import get_settings

ALGORITHM = "HS256"  # the ONLY algorithm accepted on decode (blocks alg-confusion / "none")

# Library defaults for Argon2id. (The OWASP minimum is m=19 MiB, t=2, p=1.)
_hasher = PasswordHasher()

# Verified against when the email is unknown, so "no such user" and "wrong password"
# cost about the same time and cannot be told apart by timing.
DUMMY_HASH = _hasher.hash("accessdesk-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def create_access_token(user_id: int) -> tuple[str, str, int]:
    """Return (token, jti, exp_unix). The token carries identity only, never the role.

    The role is looked up in the database on every request, so a demotion takes effect
    immediately instead of when the token expires.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.access_token_minutes)
    jti = uuid.uuid4().hex
    claims = {
        "sub": str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": exp,
        "jti": jti,
    }
    token = jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITHM)
    return token, jti, int(exp.timestamp())


def decode_access_token(token: str) -> dict:
    """Validate signature, algorithm, issuer, audience, expiry and required claims.

    Raises a jwt.PyJWTError subclass on ANY problem; callers turn that into a generic 401.
    """
    settings = get_settings()
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
    )
