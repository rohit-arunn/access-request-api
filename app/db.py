"""SQLite access. Every query uses ? placeholders; user input is never formatted into SQL."""

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone

from .config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'employee'
                  CHECK (role IN ('employee', 'approver', 'admin')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id  INTEGER NOT NULL REFERENCES users(id),
    resource      TEXT NOT NULL,
    justification TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    decided_by    INTEGER REFERENCES users(id),
    decision_note TEXT,
    created_at    TEXT NOT NULL,
    decided_at    TEXT
);

-- Logout / revocation list. Rows can be deleted once the token would have expired anyway.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

-- Who did what. Never store passwords, tokens, or request bodies here.
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    actor_id INTEGER,
    action   TEXT NOT NULL,
    target   TEXT
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    # check_same_thread=False: FastAPI may resolve a dependency and run the endpoint
    # on different worker threads. Each request still gets its own connection.
    conn = sqlite3.connect(get_settings().database_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI dependency: one connection per request, always closed."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def create_user(
    conn: sqlite3.Connection, email: str, password_hash: str, role: str = "employee"
) -> int:
    """Insert a user. The caller commits. Raises sqlite3.IntegrityError on duplicate email."""
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (email.strip().lower(), password_hash, role, utc_now()),
    )
    return int(cur.lastrowid)


def audit(
    conn: sqlite3.Connection, actor_id: int | None, action: str, target: str | None = None
) -> None:
    """Append an audit row. The caller commits."""
    conn.execute(
        "INSERT INTO audit_log (ts, actor_id, action, target) VALUES (?, ?, ?, ?)",
        (utc_now(), actor_id, action, target),
    )
