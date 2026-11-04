"""Glue between route handlers and the policy: tenant-scoped loading and enforcement.

Handlers never query tenant tables by primary key alone. ``load_project`` and
``load_document`` always filter by the organisation in the URL (and the document loader by
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
    record_event(
        session_factory,
        EventType.PERMISSION_DENIED,
        ctx,
        actor_user_id=actor.user_id,
        org_id=actor.org_id,
        detail={
            "action": str(action),
            "reason": decision.reason,
            "status": 403 if decision.visible else 404,
            **(target or {}),
        },
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


def load_document(
    session: Session,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    document_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> Document:
    stmt = select(Document).where(
        Document.id == document_id,
        Document.org_id == org_id,
        Document.project_id == project_id,
    )
    if for_update:
        stmt = stmt.with_for_update()
    document = session.execute(stmt).scalar_one_or_none()
    if document is None:
        raise not_found()
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
