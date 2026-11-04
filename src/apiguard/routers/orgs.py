"""Organisations, memberships and audit log views."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from apiguard.audit import EventType, add_event
from apiguard.authz import authorize_org, enforce, not_found
from apiguard.deps import ContextDep, CurrentUser, SessionDep, SessionFactoryDep
from apiguard.models import AuditEvent, Membership, Organization, User
from apiguard.policy import Action, Role, decide_membership_change
from apiguard.routers.auth import normalise_email
from apiguard.schemas import (
    AuditEventOut,
    MemberAdd,
    MemberOut,
    MemberUpdate,
    OrgCreate,
    OrgOut,
    OrgWithRole,
    UserOut,
)

router = APIRouter(tags=["organisations"])

Limit = Annotated[int, Query(ge=1, le=100)]


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user


@router.get("/me/audit-events", response_model=list[AuditEventOut])
def my_security_events(
    user: CurrentUser, session: SessionDep, limit: Limit = 50
) -> list[AuditEvent]:
    """Security events where the caller is the actor (logins, token reuse, denials)."""
    return list(
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.actor_user_id == user.id)
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        ).scalars()
    )


@router.post("/orgs", status_code=status.HTTP_201_CREATED, response_model=OrgOut)
def create_org(
    body: OrgCreate, user: CurrentUser, session: SessionDep, ctx: ContextDep
) -> Organization:
    org = Organization(name=body.name)
    session.add(org)
    session.flush()
    session.add(Membership(org_id=org.id, user_id=user.id, role=Role.OWNER.value))
    add_event(
        session,
        EventType.MEMBER_ADDED,
        ctx,
        actor_user_id=user.id,
        org_id=org.id,
        detail={"user_id": str(user.id), "role": Role.OWNER.value, "via": "org_created"},
    )
    session.commit()
    return org


@router.get("/orgs", response_model=list[OrgWithRole])
def list_my_orgs(user: CurrentUser, session: SessionDep) -> list[OrgWithRole]:
    rows = session.execute(
        select(Organization, Membership.role)
        .join(Membership, Membership.org_id == Organization.id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.created_at)
    ).all()
    return [OrgWithRole(id=org.id, name=org.name, role=Role(role)) for org, role in rows]


@router.get("/orgs/{org_id}", response_model=OrgWithRole)
def get_org(
    org_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> OrgWithRole:
    actor = authorize_org(
        session, user.id, org_id, Action.ORG_READ, session_factory=factory, ctx=ctx
    )
    org = session.get(Organization, org_id)
    if org is None or actor.role is None:
        raise not_found()
    return OrgWithRole(id=org.id, name=org.name, role=actor.role)


def _member_out(user: User, role: str) -> MemberOut:
    return MemberOut(
        user_id=user.id, email=user.email, display_name=user.display_name, role=Role(role)
    )


@router.get("/orgs/{org_id}/members", response_model=list[MemberOut])
def list_members(
    org_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> list[MemberOut]:
    authorize_org(session, user.id, org_id, Action.MEMBER_LIST, session_factory=factory, ctx=ctx)
    rows = session.execute(
        select(User, Membership.role)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org_id)
        .order_by(Membership.created_at)
    ).all()
    return [_member_out(u, role) for u, role in rows]


@router.post(
    "/orgs/{org_id}/members", status_code=status.HTTP_201_CREATED, response_model=MemberOut
)
def add_member(
    org_id: uuid.UUID,
    body: MemberAdd,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> MemberOut:
    actor = authorize_org(
        session, user.id, org_id, Action.MEMBER_ADD, session_factory=factory, ctx=ctx
    )
    enforce(
        decide_membership_change(actor.role, target_role=None, new_role=body.role),
        actor=actor,
        action=Action.MEMBER_ADD,
        session_factory=factory,
        ctx=ctx,
        target={"new_role": body.role.value},
    )
    target = session.execute(
        select(User).where(User.email == normalise_email(str(body.email)))
    ).scalar_one_or_none()
    if target is None:
        # Only owners/admins reach this point, and only for their own organisation.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no user with that email")
    if session.get(Membership, (org_id, target.id)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already a member")
    session.add(Membership(org_id=org_id, user_id=target.id, role=body.role.value))
    add_event(
        session,
        EventType.MEMBER_ADDED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={"user_id": str(target.id), "role": body.role.value},
    )
    session.commit()
    return _member_out(target, body.role.value)


def _load_membership(session: SessionDep, org_id: uuid.UUID, user_id: uuid.UUID) -> Membership:
    membership = session.execute(
        select(Membership)
        .where(Membership.org_id == org_id, Membership.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if membership is None:
        raise not_found()
    return membership


def _ensure_another_owner(session: SessionDep, org_id: uuid.UUID) -> None:
    # Lock all owner rows of this org so two concurrent demotions cannot both succeed.
    owners = session.execute(
        select(Membership.user_id)
        .where(Membership.org_id == org_id, Membership.role == Role.OWNER.value)
        .with_for_update()
    ).all()
    if len(owners) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "an organisation must keep an owner")


@router.patch("/orgs/{org_id}/members/{member_id}", response_model=MemberOut)
def change_role(
    org_id: uuid.UUID,
    member_id: uuid.UUID,
    body: MemberUpdate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> MemberOut:
    actor = authorize_org(
        session, user.id, org_id, Action.MEMBER_UPDATE, session_factory=factory, ctx=ctx
    )
    membership = _load_membership(session, org_id, member_id)
    old_role = Role(membership.role)
    enforce(
        decide_membership_change(actor.role, target_role=old_role, new_role=body.role),
        actor=actor,
        action=Action.MEMBER_UPDATE,
        session_factory=factory,
        ctx=ctx,
        target={"member_id": str(member_id), "new_role": body.role.value},
    )
    if old_role is Role.OWNER and body.role is not Role.OWNER:
        _ensure_another_owner(session, org_id)
    membership.role = body.role.value
    add_event(
        session,
        EventType.ROLE_CHANGED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={"user_id": str(member_id), "from": old_role.value, "to": body.role.value},
    )
    session.commit()
    target = session.get(User, member_id)
    if target is None:  # pragma: no cover - FK guarantees the user exists
        raise not_found()
    return _member_out(target, membership.role)


@router.delete("/orgs/{org_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    org_id: uuid.UUID,
    member_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    actor = authorize_org(
        session, user.id, org_id, Action.MEMBER_REMOVE, session_factory=factory, ctx=ctx
    )
    membership = _load_membership(session, org_id, member_id)
    old_role = Role(membership.role)
    enforce(
        decide_membership_change(actor.role, target_role=old_role, new_role=None),
        actor=actor,
        action=Action.MEMBER_REMOVE,
        session_factory=factory,
        ctx=ctx,
        target={"member_id": str(member_id)},
    )
    if old_role is Role.OWNER:
        _ensure_another_owner(session, org_id)
    session.delete(membership)
    add_event(
        session,
        EventType.MEMBER_REMOVED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={"user_id": str(member_id), "role": old_role.value},
    )
    session.commit()


@router.get("/orgs/{org_id}/audit-events", response_model=list[AuditEventOut])
def org_audit_events(
    org_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
    limit: Limit = 50,
    event_type: str | None = None,
) -> list[AuditEvent]:
    authorize_org(session, user.id, org_id, Action.AUDIT_READ, session_factory=factory, ctx=ctx)
    stmt = select(AuditEvent).where(AuditEvent.org_id == org_id)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    return list(session.execute(stmt.order_by(AuditEvent.id.desc()).limit(limit)).scalars())
