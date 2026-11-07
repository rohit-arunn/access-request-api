"""Request/response models.

Every INPUT model sets extra="forbid". That is the main defense against mass assignment:
a payload containing "role", "status", "requester_id", "is_active", ... is rejected with
422 instead of being silently ignored (or worse, copied into the database).
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .permissions import Role

RequestStatus = Literal["pending", "approved", "rejected", "cancelled"]

_RESOURCE_PATTERN = r"^[A-Za-z0-9 _:./-]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterIn(StrictModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginIn(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: int
    email: str
    role: Role
    is_active: bool


class RequestCreate(StrictModel):
    resource: str = Field(min_length=3, max_length=80, pattern=_RESOURCE_PATTERN)
    justification: str = Field(min_length=10, max_length=500)


class RequestUpdate(StrictModel):
    justification: str = Field(min_length=10, max_length=500)


class DecisionIn(StrictModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=300)


class RoleChangeIn(StrictModel):
    role: Role


class RequestOut(BaseModel):
    id: int
    requester_id: int
    resource: str
    justification: str
    status: RequestStatus
    decided_by: int | None
    decision_note: str | None
    created_at: str
    decided_at: str | None


class AuditOut(BaseModel):
    id: int
    ts: str
    actor_id: int | None
    action: str
    target: str | None
