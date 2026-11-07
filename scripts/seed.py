"""Create demo users and sample requests with RANDOM passwords.

Run from the project root:  python -m scripts.seed

Passwords are generated on your machine and written to demo_credentials.json, which is
gitignored. Nothing secret is committed. To start over: delete accessdesk.db and
demo_credentials.json, then run this again.
"""

import json
import secrets
import sys
from pathlib import Path

from app import db
from app.security import hash_password

CREDENTIALS_FILE = Path("demo_credentials.json")

USERS = [
    ("alice@example.test", "employee"),
    ("bob@example.test", "employee"),
    ("carol@example.test", "approver"),
    ("dave@example.test", "admin"),
]

SAMPLE_REQUESTS = [
    ("alice@example.test", "prod-db:read", "Need read access to debug the nightly ETL failure."),
    ("alice@example.test", "wiki:edit", "Updating the on-call runbook for my team."),
    ("bob@example.test", "billing-dashboard:view", "Preparing the quarterly cost review."),
]


def main() -> int:
    db.init_db()
    conn = db.connect()
    try:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            print(
                "Users already exist; not reseeding. Delete the database file and "
                f"{CREDENTIALS_FILE} to start over."
            )
            return 0

        credentials: dict[str, dict[str, str]] = {}
        ids: dict[str, int] = {}
        for email, role in USERS:
            password = secrets.token_urlsafe(16)
            ids[email] = db.create_user(conn, email, hash_password(password), role)
            credentials[email] = {"password": password, "role": role}

        for email, resource, justification in SAMPLE_REQUESTS:
            conn.execute(
                "INSERT INTO access_requests (requester_id, resource, justification, created_at) "
                "VALUES (?, ?, ?, ?)",
                (ids[email], resource, justification, db.utc_now()),
            )
        conn.commit()
    finally:
        conn.close()

    CREDENTIALS_FILE.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    print(f"Seeded {len(USERS)} users and {len(SAMPLE_REQUESTS)} requests.")
    print(f"Demo passwords written to {CREDENTIALS_FILE} (gitignored). They are not printed here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
