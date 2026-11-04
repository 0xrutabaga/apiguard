"""Glue between route handlers and the policy: tenant-scoped loading and enforcement.

Handlers never query tenant tables by primary key alone. ``load_project`` and
``authorize_document`` always filter by the organisation in the URL (and the document loader by
project too), so a handler that forgot an authorization call would still get 404 for another
tenant's id instead of the row.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.audit import EventType, RequestContext, record_event
from apiguard.models import Document, DocumentShare, Membership, Project
from apiguard.policy import (
    Action,
    Actor,
    Decision,
    DocumentResource,
    OrgResource,
    Resource,
    Role,
    SharePermission,
    decide,
)

NOT_FOUND = "not found"
FORBIDDEN = "forbidden"


def not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)


def resolve_actor(session: Session, user_id: uuid.UUID, org_id: uuid.UUID) -> Actor:
    role = session.execute(
        select(Membership.role).where(Membership.org_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    return Actor(user_id=user_id, org_id=org_id, role=Role(role) if role else None)


# Recorded for every 404 the policy layer produces, whether the resource is missing or only
# invisible to the caller. The policy's own reason is not stored for 404s: a caller can read
# their own events (GET /me/audit-events), and "not visible" versus "missing" would tell them
# that an id exists.
NOT_VISIBLE_REASON = "not found or not visible"


def _record_denial(
    *,
    actor: Actor,
    action: Action | str,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
    visible: bool,
    reason: str,
    target: dict[str, str] | None,
) -> None:
    record_event(
        session_factory,
        EventType.PERMISSION_DENIED,
        ctx,
        actor_user_id=actor.user_id,
        org_id=actor.org_id,
        detail={
            "action": str(action),
            "reason": reason if visible else NOT_VISIBLE_REASON,
            "status": 403 if visible else 404,
            **(target or {}),
        },
    )


def deny_not_found(
    *,
    actor: Actor,
    action: Action | str,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
    target: dict[str, str] | None = None,
) -> HTTPException:
    """Audit a 404 exactly like an invisible-resource denial and return the exception."""
    _record_denial(
        actor=actor,
        action=action,
        session_factory=session_factory,
        ctx=ctx,
        visible=False,
        reason=NOT_VISIBLE_REASON,
        target=target,
    )
    return not_found()


def enforce(
    decision: Decision,
    *,
    actor: Actor,
    action: Action | str,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
    target: dict[str, str] | None = None,
) -> None:
    """Raise 404 (invisible) or 403 (visible, not allowed) and audit the denial."""
    if decision.allowed:
        return
    _record_denial(
        actor=actor,
        action=action,
        session_factory=session_factory,
        ctx=ctx,
        visible=decision.visible,
        reason=decision.reason,
        target=target,
    )
    if not decision.visible:
        raise not_found()
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN)


def authorize(
    actor: Actor,
    action: Action,
    resource: Resource,
    *,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
    target: dict[str, str] | None = None,
) -> None:
    enforce(
        decide(actor, action, resource),
        actor=actor,
        action=action,
        session_factory=session_factory,
        ctx=ctx,
        target=target,
    )


def authorize_org(
    session: Session,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    action: Action,
    *,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
) -> Actor:
    actor = resolve_actor(session, user_id, org_id)
    authorize(actor, action, OrgResource(org_id), session_factory=session_factory, ctx=ctx)
    return actor


def load_project(session: Session, org_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    project = session.execute(
        select(Project).where(Project.id == project_id, Project.org_id == org_id)
    ).scalar_one_or_none()
    if project is None:
        raise not_found()
    return project


def authorize_document(
    session: Session,
    actor: Actor,
    action: Action,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    *,
    session_factory: sessionmaker[Session],
    ctx: RequestContext,
    for_update: bool = False,
) -> Document:
    """Load a document in the caller's tenant and authorize ``action`` on it.

    A document that does not exist and one the caller may not see produce the same 404 and the
    same audit row, so neither the response nor the caller's own audit trail reveals existence.
    """
    target = {"document_id": str(document_id)}
    stmt = select(Document).where(
        Document.id == document_id,
        Document.org_id == org_id,
        Document.project_id == project_id,
    )
    if for_update:
        stmt = stmt.with_for_update()
    document = session.execute(stmt).scalar_one_or_none()
    if document is None:
        raise deny_not_found(
            actor=actor, action=action, session_factory=session_factory, ctx=ctx, target=target
        )
    authorize(
        actor,
        action,
        document_resource(session, actor, document),
        session_factory=session_factory,
        ctx=ctx,
        target=target,
    )
    return document


def document_resource(session: Session, actor: Actor, document: Document) -> DocumentResource:
    permission = session.execute(
        select(DocumentShare.permission).where(
            DocumentShare.document_id == document.id,
            DocumentShare.org_id == document.org_id,
            DocumentShare.user_id == actor.user_id,
        )
    ).scalar_one_or_none()
    return DocumentResource(
        org_id=document.org_id,
        owner_id=document.owner_id,
        share=SharePermission(permission) if permission else None,
    )
