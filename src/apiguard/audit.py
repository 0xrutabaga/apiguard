"""Append-only audit log of security events.

Two ways to write an event, chosen by whether the event must survive the request failing:

* ``add_event`` adds the row to the caller's session, so it commits or rolls back together
  with the change it describes (used for role changes and membership changes).
* ``record_event`` writes in its own short transaction and commits immediately. It is used for
  events emitted on the way to an error response (failed login, permission denied, refresh
  token reuse), where the request's own transaction will not be committed.

The table itself rejects UPDATE and DELETE through a trigger (see the initial migration).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import AuditEvent


class EventType(StrEnum):
    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    RATE_LIMITED = "rate_limited"
    REFRESH_ROTATED = "refresh_rotated"
    REFRESH_TOKEN_REUSED = "refresh_token_reused"  # noqa: S105 - event name, not a secret
    LOGOUT = "logout"
    PERMISSION_DENIED = "permission_denied"
    INVITATION_CREATED = "invitation_created"
    INVITATION_REVOKED = "invitation_revoked"
    MEMBER_ADDED = "member_added"
    MEMBER_REMOVED = "member_removed"
    ROLE_CHANGED = "role_changed"


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    client_ip: str


def _build(
    event_type: EventType,
    ctx: RequestContext,
    actor_user_id: uuid.UUID | None,
    org_id: uuid.UUID | None,
    detail: dict[str, Any] | None,
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type.value,
        actor_user_id=actor_user_id,
        org_id=org_id,
        request_id=ctx.request_id,
        client_ip=ctx.client_ip,
        detail=detail or {},
    )


def add_event(
    session: Session,
    event_type: EventType,
    ctx: RequestContext,
    *,
    actor_user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(_build(event_type, ctx, actor_user_id, org_id, detail))


def record_event(
    session_factory: sessionmaker[Session],
    event_type: EventType,
    ctx: RequestContext,
    *,
    actor_user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    with session_factory.begin() as session:
        session.add(_build(event_type, ctx, actor_user_id, org_id, detail))
