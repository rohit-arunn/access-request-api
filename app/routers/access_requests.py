"""Access requests: the business workflow, with RBAC plus object-level authorization.

Two layers protect every route:
  1. require_permission(...)  -> does this ROLE allow this kind of action at all?
  2. _fetch_visible/_fetch_owned -> may this USER touch THIS record?
"""

import logging
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import db as dbm
from ..deps import CurrentUser, require_permission
from ..permissions import Permission
from ..schemas import DecisionIn, RequestCreate, RequestOut, RequestStatus, RequestUpdate

router = APIRouter(prefix="/requests", tags=["access requests"])
log = logging.getLogger("accessdesk.requests")

# Fixed column list; only constant text is ever placed in SQL strings.
COLS = (
    "id, requester_id, resource, justification, status, "
    "decided_by, decision_note, created_at, decided_at"
)


def _fetch_visible(conn: sqlite3.Connection, request_id: int, user: CurrentUser) -> sqlite3.Row:
    """Return the request if this user may SEE it, else 404.

    404 (not 403) for other people's records: a 403 would confirm that the ID exists,
    letting an attacker enumerate IDs.
    """
    row = conn.execute(
        f"SELECT {COLS} FROM access_requests WHERE id = ?", (request_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    if row["requester_id"] != user.id and not user.can(Permission.REQUEST_READ_ALL):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    return row


def _fetch_owned(conn: sqlite3.Connection, request_id: int, user: CurrentUser) -> sqlite3.Row:
    """Return the request only if this user OWNS it. Even admins cannot edit others' requests."""
    row = _fetch_visible(conn, request_id, user)
    if row["requester_id"] != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the requester can modify this request")
    return row


@router.post("", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
def create_request(
    body: RequestCreate,
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_CREATE)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    # requester_id comes from the verified token, never from the payload.
    cur = conn.execute(
        "INSERT INTO access_requests (requester_id, resource, justification, created_at) "
        "VALUES (?, ?, ?, ?)",
        (user.id, body.resource, body.justification, dbm.utc_now()),
    )
    request_id = int(cur.lastrowid)
    dbm.audit(conn, user.id, "request.create", f"request:{request_id}")
    conn.commit()
    return dict(_fetch_visible(conn, request_id, user))


@router.get("", response_model=list[RequestOut])
def list_requests(
    scope: Literal["mine", "all"] = "mine",
    status_filter: RequestStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_READ_OWN)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    if scope == "all" and not user.can(Permission.REQUEST_READ_ALL):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")

    clauses: list[str] = []
    params: list[object] = []
    if scope == "mine":
        clauses.append("requester_id = ?")
        params.append(user.id)
    if status_filter is not None:
        clauses.append("status = ?")
        params.append(status_filter)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""  # constant fragments only

    rows = conn.execute(
        f"SELECT {COLS} FROM access_requests {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


@router.get("/{request_id}", response_model=RequestOut)
def get_request(
    request_id: int,
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_READ_OWN)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    return dict(_fetch_visible(conn, request_id, user))


@router.patch("/{request_id}", response_model=RequestOut)
def update_request(
    request_id: int,
    body: RequestUpdate,
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_CREATE)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    """Owner may reword the justification while pending. Status can NOT be set here:
    RequestUpdate has no status field and forbids extras."""
    row = _fetch_owned(conn, request_id, user)
    if row["status"] != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only pending requests can be edited")
    conn.execute(
        "UPDATE access_requests SET justification = ? "
        "WHERE id = ? AND requester_id = ? AND status = 'pending'",
        (body.justification, request_id, user.id),
    )
    dbm.audit(conn, user.id, "request.update", f"request:{request_id}")
    conn.commit()
    return dict(_fetch_visible(conn, request_id, user))


@router.post("/{request_id}/cancel", response_model=RequestOut)
def cancel_request(
    request_id: int,
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_CREATE)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    row = _fetch_owned(conn, request_id, user)
    cur = conn.execute(
        "UPDATE access_requests SET status = 'cancelled' "
        "WHERE id = ? AND requester_id = ? AND status = 'pending'",
        (request_id, user.id),
    )
    if cur.rowcount == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only pending requests can be cancelled")
    dbm.audit(conn, user.id, "request.cancel", f"request:{row['id']}")
    conn.commit()
    return dict(_fetch_visible(conn, request_id, user))


@router.post("/{request_id}/decision", response_model=RequestOut)
def decide_request(
    request_id: int,
    body: DecisionIn,
    user: CurrentUser = Depends(require_permission(Permission.REQUEST_DECIDE)),
    conn: sqlite3.Connection = Depends(dbm.get_db),
):
    row = _fetch_visible(conn, request_id, user)

    # Separation of duties: nobody approves their own access, whatever their role.
    if row["requester_id"] == user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot decide your own request")

    new_status = "approved" if body.decision == "approve" else "rejected"
    # "AND status = 'pending'" makes the check-and-update atomic: two approvers racing
    # on the same request cannot both succeed.
    cur = conn.execute(
        "UPDATE access_requests "
        "SET status = ?, decided_by = ?, decision_note = ?, decided_at = ? "
        "WHERE id = ? AND status = 'pending'",
        (new_status, user.id, body.note, dbm.utc_now(), request_id),
    )
    if cur.rowcount == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Request is not pending")
    dbm.audit(conn, user.id, f"request.{new_status}", f"request:{request_id}")
    conn.commit()
    return dict(_fetch_visible(conn, request_id, user))
