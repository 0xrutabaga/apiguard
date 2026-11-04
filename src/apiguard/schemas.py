"""Request and response models.

Request models are write allow-lists: ``extra="forbid"`` rejects any field that is not
declared, so a client cannot set ``org_id``, ``owner_id``, ``role`` or ``password_hash`` by
adding them to a body (mass assignment). Response models list exactly what may leave the
service; none of them has a password hash or token hash field.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from apiguard.policy import Role, SharePermission

MIN_PASSWORD_LENGTH = 12
# Argon2 cost does not depend on length much, but bounding input size limits abuse.
MAX_PASSWORD_LENGTH = 128


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    display_name: str = Field(min_length=1, max_length=100)


class LoginRequest(StrictModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=1, max_length=200)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str


class OrgCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str


class OrgWithRole(OrgOut):
    role: Role


class MemberAdd(StrictModel):
    email: EmailStr = Field(max_length=320)
    role: Role


class MemberUpdate(StrictModel):
    role: Role


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    role: Role


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class ProjectUpdate(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str


class DocumentCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=100_000)


class DocumentUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = Field(default=None, max_length=100_000)


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    project_id: uuid.UUID
    owner_id: uuid.UUID
    title: str
    body: str
    created_at: datetime
    updated_at: datetime


class ShareUpdate(StrictModel):
    permission: SharePermission


class ShareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    document_id: uuid.UUID
    user_id: uuid.UUID
    permission: SharePermission


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    event_type: str
    actor_user_id: uuid.UUID | None
    org_id: uuid.UUID | None
    request_id: str | None
    client_ip: str | None
    detail: dict[str, Any]
