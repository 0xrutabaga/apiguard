"""Invitations: the only way to join an existing organisation.

Owners and admins invite an email address with a role. The response is the same whether or
not that email has an account (nothing is looked up), and it contains no profile data, so
inviting cannot be used to enumerate users. The invitee becomes a member only by accepting,
which needs the one-time token (returned once to the inviter, who passes it on out of band;
a production deployment would email it) and a logged-in account with the invited email.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from apiguard.audit import EventType, add_event
from apiguard.authz import authorize_org, enforce, not_found
from apiguard.deps import (
    ContextDep,
    CurrentUser,
    RateLimiterDep,
    SessionDep,
    SessionFactoryDep,
    SettingsDep,
)
from apiguard.models import Invitation, Membership, Organization
from apiguard.policy import Action, Role, decide_membership_change
from apiguard.ratelimit import Limit
from apiguard.routers.auth import apply_limits, normalise_email
from apiguard.schemas import (
    AcceptInvitation,
    InvitationCreate,
    InvitationCreated,
    InvitationOut,
    OrgWithRole,
)

router = APIRouter(tags=["invitations"])

INVALID_INVITATION = "invalid or expired invitation"


def hash_invitation_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


@router.post(
    "/orgs/{org_id}/invitations",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvitationCreated,
)
def create_invitation(
    org_id: uuid.UUID,
    body: InvitationCreate,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    settings: SettingsDep,
    limiter: RateLimiterDep,
    ctx: ContextDep,
) -> InvitationCreated:
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
    apply_limits(
        limiter,
        [Limit(f"invite:user:{user.id}", settings.invite_limit_per_actor)],
        factory,
        ctx,
        "invite",
    )
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.invitation_ttl_seconds)
    email = normalise_email(str(body.email))
    # Re-inviting the same email replaces role, token and expiry; the old token stops working.
    stmt = (
        insert(Invitation)
        .values(
            id=uuid.uuid4(),
            org_id=org_id,
            email=email,
            role=body.role.value,
            token_hash=hash_invitation_token(token),
            invited_by=user.id,
            expires_at=expires_at,
        )
        .on_conflict_do_update(
            index_elements=[Invitation.org_id, Invitation.email],
            set_={
                "role": body.role.value,
                "token_hash": hash_invitation_token(token),
                "invited_by": user.id,
                "expires_at": expires_at,
            },
        )
        .returning(Invitation.id)
    )
    invitation_id = session.execute(stmt).scalar_one()
    add_event(
        session,
        EventType.INVITATION_CREATED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={"invitation_id": str(invitation_id), "role": body.role.value},
    )
    session.commit()
    return InvitationCreated(
        id=invitation_id,
        org_id=org_id,
        email=email,
        role=body.role,
        expires_at=expires_at,
        token=token,
    )


@router.get("/orgs/{org_id}/invitations", response_model=list[InvitationOut])
def list_invitations(
    org_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> list[Invitation]:
    authorize_org(session, user.id, org_id, Action.MEMBER_ADD, session_factory=factory, ctx=ctx)
    return list(
        session.execute(
            select(Invitation)
            .where(Invitation.org_id == org_id)
            .order_by(Invitation.created_at, Invitation.id)
        ).scalars()
    )


@router.delete("/orgs/{org_id}/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invitation(
    org_id: uuid.UUID,
    invitation_id: uuid.UUID,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    ctx: ContextDep,
) -> None:
    actor = authorize_org(
        session, user.id, org_id, Action.MEMBER_ADD, session_factory=factory, ctx=ctx
    )
    invitation = session.execute(
        select(Invitation).where(Invitation.id == invitation_id, Invitation.org_id == org_id)
    ).scalar_one_or_none()
    if invitation is None:
        raise not_found()
    # An admin may not revoke an invitation they could not have created (owner/admin role).
    enforce(
        decide_membership_change(actor.role, target_role=Role(invitation.role), new_role=None),
        actor=actor,
        action=Action.MEMBER_ADD,
        session_factory=factory,
        ctx=ctx,
        target={"invitation_id": str(invitation_id)},
    )
    session.delete(invitation)
    add_event(
        session,
        EventType.INVITATION_REVOKED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={"invitation_id": str(invitation_id)},
    )
    session.commit()


@router.post("/invitations/accept", status_code=status.HTTP_201_CREATED, response_model=OrgWithRole)
def accept_invitation(
    body: AcceptInvitation,
    user: CurrentUser,
    session: SessionDep,
    factory: SessionFactoryDep,
    settings: SettingsDep,
    limiter: RateLimiterDep,
    ctx: ContextDep,
) -> OrgWithRole:
    apply_limits(
        limiter,
        [Limit(f"accept:user:{user.id}", settings.invite_limit_per_actor)],
        factory,
        ctx,
        "accept",
    )
    invitation = session.execute(
        select(Invitation)
        .where(Invitation.token_hash == hash_invitation_token(body.token))
        .with_for_update()
    ).scalar_one_or_none()
    # Unknown token, expired, or issued to a different email: one indistinguishable answer.
    if (
        invitation is None
        or invitation.expires_at <= datetime.now(UTC)
        or invitation.email != user.email
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, INVALID_INVITATION)
    if session.get(Membership, (invitation.org_id, user.id)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already a member")

    org_id, role = invitation.org_id, Role(invitation.role)
    session.add(Membership(org_id=org_id, user_id=user.id, role=role.value))
    session.delete(invitation)
    add_event(
        session,
        EventType.MEMBER_ADDED,
        ctx,
        actor_user_id=user.id,
        org_id=org_id,
        detail={
            "user_id": str(user.id),
            "role": role.value,
            "via": "invitation",
            "invited_by": str(invitation.invited_by) if invitation.invited_by else None,
        },
    )
    session.commit()
    org = session.get(Organization, org_id)
    if org is None:  # pragma: no cover - FK guarantees the organisation exists
        raise not_found()
    return OrgWithRole(id=org.id, name=org.name, role=role)
