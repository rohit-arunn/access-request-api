"""Roles and permissions.

Three separate ideas live in this project, and they are deliberately kept apart:
  * Authentication: who are you?            (security.py, deps.get_current_user)
  * Roles/permissions: what may your kind of user do?   (this file)
  * Ownership: may you touch THIS record?    (routers/access_requests.py)
"""

from enum import StrEnum


class Role(StrEnum):
    EMPLOYEE = "employee"
    APPROVER = "approver"
    ADMIN = "admin"


class Permission(StrEnum):
    REQUEST_CREATE = "request:create"
    REQUEST_READ_OWN = "request:read_own"
    REQUEST_READ_ALL = "request:read_all"
    REQUEST_DECIDE = "request:decide"
    USER_MANAGE_ROLES = "user:manage_roles"
    AUDIT_READ = "audit:read"


# The single source of truth for "what can a role do". Tests and docs mirror this table.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.EMPLOYEE: frozenset(
        {Permission.REQUEST_CREATE, Permission.REQUEST_READ_OWN}
    ),
    Role.APPROVER: frozenset(
        {
            Permission.REQUEST_CREATE,
            Permission.REQUEST_READ_OWN,
            Permission.REQUEST_READ_ALL,
            Permission.REQUEST_DECIDE,
        }
    ),
    Role.ADMIN: frozenset(Permission),  # every permission
}
