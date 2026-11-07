"""Admin-only endpoints: role changes and the audit log."""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import db as dbm
from ..deps import CurrentUser, require_permission
from ..permissions import Permission
from ..schemas import AuditOut, RoleChangeIn, UserOut

router = APIRouter(prefix="/admin", tags=["admin"])


@router.put("/users/{user_id}/role", response_model=UserOut)
def set_role(
    user_id: int,
    body: RoleChangeIn,
    admin: CurrentUser = Depends(require_permission(Permission.USER_MANAGE_ROLES)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    # Blocks an admin from demoting themselves into a state with no admin left,
    # and keeps "who changed whose role" unambiguous in the audit log.
    if user_id == admin.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot change your own role")

    row = conn.execute(
        "SELECT id, email, role, is_active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.role.value, user_id))
    dbm.audit(conn, admin.id, "user.role_change", f"user:{user_id} {row['role']}->{body.role.value}")
    conn.commit()
    return UserOut(
        id=row["id"], email=row["email"], role=body.role, is_active=bool(row["is_active"])
    )


@router.get("/audit", response_model=list[AuditOut])
def read_audit(
    limit: int = Query(default=50, ge=1, le=200),
    _admin: CurrentUser = Depends(require_permission(Permission.AUDIT_READ)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    rows = conn.execute(
        "SELECT id, ts, actor_id, action, target FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
