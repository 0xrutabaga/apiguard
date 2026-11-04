"""The single authorization policy: (actor, action, resource) -> Decision.

Every route handler calls ``decide`` (through ``apiguard.authz.authorize``) before it reads or
changes tenant data, and document listings use ``visible_documents_clause``, which encodes the
same read rule as SQL. The two are checked against each other in
tests/integration/test_policy_sql_agreement.py.

A Decision has two parts:

* ``visible``: may the actor know the resource exists? If not, the API answers 404, exactly as
  for a resource that does not exist, so ids from another tenant reveal nothing.
* ``allowed``: may the actor perform the action? A visible but disallowed action is a 403.

Roles inside an organisation, from most to least privileged: owner, admin, editor, viewer.

Organisation and project actions
    ORG_READ, PROJECT_READ, MEMBER_LIST          every member
    PROJECT_CREATE / UPDATE / DELETE, AUDIT_READ owner, admin
    MEMBER_ADD / MEMBER_UPDATE / MEMBER_REMOVE   owner, admin (target rules in
                                                 ``decide_membership_change``)
    DOCUMENT_CREATE                              owner, admin, editor

Document actions
    owner, admin          see and do everything with every document in the org
    document owner        read; update, delete and share while their role is editor or above
    shared "edit"         read; update while their role is editor or above
    shared "read"         read
    anyone else           the document is invisible (404)

A share never raises a member above their role's ceiling: a viewer with an "edit" share can
only read. Because roles are looked up on every request, demoting a member immediately
narrows what their existing shares allow.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from sqlalchemy import ColumnElement, exists, false, or_, select

from apiguard.models import Document, DocumentShare


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


class SharePermission(StrEnum):
    READ = "read"
    EDIT = "edit"


class Action(StrEnum):
    ORG_READ = "org.read"
    MEMBER_LIST = "member.list"
    MEMBER_ADD = "member.add"
    MEMBER_UPDATE = "member.update"
    MEMBER_REMOVE = "member.remove"
    AUDIT_READ = "audit.read"
    PROJECT_CREATE = "project.create"
    PROJECT_READ = "project.read"
    PROJECT_UPDATE = "project.update"
    PROJECT_DELETE = "project.delete"
    DOCUMENT_CREATE = "document.create"
    DOCUMENT_READ = "document.read"
    DOCUMENT_UPDATE = "document.update"
    DOCUMENT_DELETE = "document.delete"
    DOCUMENT_SHARE = "document.share"


ORG_ACTIONS = frozenset(
    {
        Action.ORG_READ,
        Action.MEMBER_LIST,
        Action.MEMBER_ADD,
        Action.MEMBER_UPDATE,
        Action.MEMBER_REMOVE,
        Action.AUDIT_READ,
        Action.PROJECT_CREATE,
        Action.PROJECT_READ,
        Action.PROJECT_UPDATE,
        Action.PROJECT_DELETE,
        Action.DOCUMENT_CREATE,
    }
)
DOCUMENT_ACTIONS = frozenset(
    {
        Action.DOCUMENT_READ,
        Action.DOCUMENT_UPDATE,
        Action.DOCUMENT_DELETE,
        Action.DOCUMENT_SHARE,
    }
)

_ALL = frozenset(Role)
_MANAGERS = frozenset({Role.OWNER, Role.ADMIN})

ORG_ACTION_ROLES: dict[Action, frozenset[Role]] = {
    Action.ORG_READ: _ALL,
    Action.MEMBER_LIST: _ALL,
    Action.PROJECT_READ: _ALL,
    Action.MEMBER_ADD: _MANAGERS,
    Action.MEMBER_UPDATE: _MANAGERS,
    Action.MEMBER_REMOVE: _MANAGERS,
    Action.AUDIT_READ: _MANAGERS,
    Action.PROJECT_CREATE: _MANAGERS,
    Action.PROJECT_UPDATE: _MANAGERS,
    Action.PROJECT_DELETE: _MANAGERS,
    Action.DOCUMENT_CREATE: frozenset({Role.OWNER, Role.ADMIN, Role.EDITOR}),
}


class Access(IntEnum):
    """What an actor can do with one document, in increasing order."""

    NONE = 0
    READ = 1
    EDIT = 2  # read + update
    MANAGE = 3  # read + update + delete + share


_ACCESS_REQUIRED: dict[Action, Access] = {
    Action.DOCUMENT_READ: Access.READ,
    Action.DOCUMENT_UPDATE: Access.EDIT,
    Action.DOCUMENT_DELETE: Access.MANAGE,
    Action.DOCUMENT_SHARE: Access.MANAGE,
}

# The highest document access each role can ever reach through ownership or a share.
_ROLE_CEILING: dict[Role, Access] = {
    Role.OWNER: Access.MANAGE,
    Role.ADMIN: Access.MANAGE,
    Role.EDITOR: Access.MANAGE,
    Role.VIEWER: Access.READ,
}


@dataclass(frozen=True)
class Actor:
    """An authenticated user acting inside one organisation.

    ``role`` is None when the user is not a member of ``org_id``.
    """

    user_id: uuid.UUID
    org_id: uuid.UUID
    role: Role | None


@dataclass(frozen=True)
class OrgResource:
    org_id: uuid.UUID


@dataclass(frozen=True)
class DocumentResource:
    org_id: uuid.UUID
    owner_id: uuid.UUID
    # The share granted to the acting user on this document, if any.
    share: SharePermission | None = None


Resource = OrgResource | DocumentResource


@dataclass(frozen=True)
class Decision:
    allowed: bool
    visible: bool
    reason: str


def _deny_invisible(reason: str) -> Decision:
    return Decision(allowed=False, visible=False, reason=reason)


def document_access(actor: Actor, resource: DocumentResource) -> Access:
    if actor.role is None or actor.org_id != resource.org_id:
        return Access.NONE
    if actor.role in _MANAGERS:
        return Access.MANAGE
    granted = Access.NONE
    if resource.owner_id == actor.user_id:
        granted = Access.MANAGE
    elif resource.share is SharePermission.EDIT:
        granted = Access.EDIT
    elif resource.share is SharePermission.READ:
        granted = Access.READ
    return min(granted, _ROLE_CEILING[actor.role])


def decide(actor: Actor, action: Action, resource: Resource) -> Decision:
    if actor.role is None:
        return _deny_invisible("not a member of the organisation")
    if actor.org_id != resource.org_id:
        return _deny_invisible("resource belongs to another organisation")

    if isinstance(resource, OrgResource):
        if action not in ORG_ACTIONS:
            return Decision(False, True, f"{action} is not an organisation action")
        if actor.role in ORG_ACTION_ROLES[action]:
            return Decision(True, True, f"role {actor.role} may {action}")
        return Decision(False, True, f"role {actor.role} may not {action}")

    if action not in DOCUMENT_ACTIONS:
        return Decision(False, True, f"{action} is not a document action")
    access = document_access(actor, resource)
    if access is Access.NONE:
        return _deny_invisible("document is not visible to this member")
    if access >= _ACCESS_REQUIRED[action]:
        return Decision(True, True, f"access {access.name.lower()} permits {action}")
    return Decision(False, True, f"access {access.name.lower()} does not permit {action}")


def visible_documents_clause(actor: Actor) -> ColumnElement[bool]:
    """SQL predicate on ``Document`` equal to ``document_access(...) >= READ``.

    Listing endpoints filter with this clause so a list never contains a document that the
    per-object check would hide.
    """
    if actor.role is None:
        return false()
    in_org = Document.org_id == actor.org_id
    if actor.role in _MANAGERS:
        return in_org
    shared_with_actor = exists(
        select(DocumentShare.document_id).where(
            DocumentShare.document_id == Document.id,
            DocumentShare.org_id == Document.org_id,
            DocumentShare.user_id == actor.user_id,
        )
    )
    return in_org & or_(Document.owner_id == actor.user_id, shared_with_actor)


def decide_membership_change(
    actor_role: Role | None,
    *,
    target_role: Role | None,
    new_role: Role | None,
) -> Decision:
    """May ``actor_role`` add, change or remove a member?

    * Adding: ``target_role`` is None, ``new_role`` is the role to grant.
    * Changing: both are set.
    * Removing: ``new_role`` is None.

    Owners may do anything (the "keep at least one owner" rule is a data invariant checked by
    the handler). Admins may only manage editors and viewers and may only grant editor or
    viewer, so an admin cannot create admins or owners or demote an owner. Nobody can grant a
    role above their own.
    """
    if actor_role is None:
        return _deny_invisible("not a member of the organisation")
    if actor_role is Role.OWNER:
        return Decision(True, True, "owners manage all memberships")
    if actor_role is Role.ADMIN:
        manageable = {Role.EDITOR, Role.VIEWER}
        if target_role is not None and target_role not in manageable:
            return Decision(False, True, f"admins may not modify a member with role {target_role}")
        if new_role is not None and new_role not in manageable:
            return Decision(False, True, f"admins may not grant role {new_role}")
        return Decision(True, True, "admins manage editors and viewers")
    return Decision(False, True, f"role {actor_role} may not manage memberships")
