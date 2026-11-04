"""Table-driven tests for apiguard.policy: every role x every action.

The expected tables below are written out by hand rather than derived from the policy module,
so a change to the policy has to be made in two places on purpose.
"""

from __future__ import annotations

import uuid

import pytest

from apiguard.policy import (
    DOCUMENT_ACTIONS,
    ORG_ACTIONS,
    Action,
    Actor,
    DocumentResource,
    OrgResource,
    Role,
    SharePermission,
    decide,
    decide_membership_change,
)

ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
ME = uuid.uuid4()
SOMEONE_ELSE = uuid.uuid4()

OW, AD, ED, VI = Role.OWNER, Role.ADMIN, Role.EDITOR, Role.VIEWER

EXPECTED_ORG: dict[Action, set[Role]] = {
    Action.ORG_READ: {OW, AD, ED, VI},
    Action.MEMBER_LIST: {OW, AD, ED, VI},
    Action.PROJECT_READ: {OW, AD, ED, VI},
    Action.MEMBER_ADD: {OW, AD},
    Action.MEMBER_UPDATE: {OW, AD},
    Action.MEMBER_REMOVE: {OW, AD},
    Action.AUDIT_READ: {OW, AD},
    Action.PROJECT_CREATE: {OW, AD},
    Action.PROJECT_UPDATE: {OW, AD},
    Action.PROJECT_DELETE: {OW, AD},
    Action.DOCUMENT_CREATE: {OW, AD, ED},
}

# Relationship of the acting member to the document.
OWNS = "owns"
SHARED_EDIT = "shared_edit"
SHARED_READ = "shared_read"
UNRELATED = "unrelated"

R, U, D, S = (
    Action.DOCUMENT_READ,
    Action.DOCUMENT_UPDATE,
    Action.DOCUMENT_DELETE,
    Action.DOCUMENT_SHARE,
)
EVERYTHING = {R, U, D, S}

# (role, relationship) -> allowed actions. Missing READ means the document is invisible.
EXPECTED_DOCUMENT: dict[tuple[Role, str], set[Action]] = {
    (OW, OWNS): EVERYTHING,
    (OW, SHARED_EDIT): EVERYTHING,
    (OW, SHARED_READ): EVERYTHING,
    (OW, UNRELATED): EVERYTHING,
    (AD, OWNS): EVERYTHING,
    (AD, SHARED_EDIT): EVERYTHING,
    (AD, SHARED_READ): EVERYTHING,
    (AD, UNRELATED): EVERYTHING,
    (ED, OWNS): EVERYTHING,
    (ED, SHARED_EDIT): {R, U},
    (ED, SHARED_READ): {R},
    (ED, UNRELATED): set(),
    # AD viewer's role ceiling is read, whatever the share or ownership says.
    (VI, OWNS): {R},
    (VI, SHARED_EDIT): {R},
    (VI, SHARED_READ): {R},
    (VI, UNRELATED): set(),
}


def test_expected_tables_cover_every_action() -> None:
    assert set(EXPECTED_ORG) == set(ORG_ACTIONS)
    assert set(DOCUMENT_ACTIONS) == EVERYTHING
    assert set(Action) == set(ORG_ACTIONS) | set(DOCUMENT_ACTIONS)


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", sorted(ORG_ACTIONS))
def test_org_action_matrix(role: Role, action: Action) -> None:
    decision = decide(Actor(ME, ORG, role), action, OrgResource(ORG))
    assert decision.visible, "members can always see their own organisation"
    assert decision.allowed is (role in EXPECTED_ORG[action])


def _document(relationship: str) -> DocumentResource:
    owner = ME if relationship == OWNS else SOMEONE_ELSE
    share = {
        SHARED_EDIT: SharePermission.EDIT,
        SHARED_READ: SharePermission.READ,
    }.get(relationship)
    return DocumentResource(org_id=ORG, owner_id=owner, share=share)


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("relationship", [OWNS, SHARED_EDIT, SHARED_READ, UNRELATED])
@pytest.mark.parametrize("action", sorted(DOCUMENT_ACTIONS))
def test_document_action_matrix(role: Role, relationship: str, action: Action) -> None:
    expected = EXPECTED_DOCUMENT[(role, relationship)]
    decision = decide(Actor(ME, ORG, role), action, _document(relationship))
    assert decision.allowed is (action in expected)
    # Invisible exactly when the member could not even read it: 404 rather than 403.
    assert decision.visible is (R in expected)


@pytest.mark.parametrize("action", list(Action))
def test_non_member_sees_nothing(action: Action) -> None:
    resource = OrgResource(ORG) if action in ORG_ACTIONS else DocumentResource(ORG, owner_id=ME)
    decision = decide(Actor(ME, ORG, None), action, resource)
    assert not decision.allowed
    assert not decision.visible


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", list(Action))
def test_role_in_one_org_grants_nothing_in_another(role: Role, action: Action) -> None:
    # The actor is an owner/admin/... of ORG but the resource belongs to OTHER_ORG, even if
    # the resource claims the actor owns it or has a share.
    resource = (
        OrgResource(OTHER_ORG)
        if action in ORG_ACTIONS
        else DocumentResource(OTHER_ORG, owner_id=ME, share=SharePermission.EDIT)
    )
    decision = decide(Actor(ME, ORG, role), action, resource)
    assert not decision.allowed
    assert not decision.visible


def test_document_action_on_org_resource_is_denied() -> None:
    decision = decide(Actor(ME, ORG, OW), Action.DOCUMENT_READ, OrgResource(ORG))
    assert not decision.allowed


def test_org_action_on_document_resource_is_denied() -> None:
    decision = decide(Actor(ME, ORG, OW), Action.PROJECT_CREATE, DocumentResource(ORG, ME))
    assert not decision.allowed


# --- membership changes ----------------------------------------------------------------

ROLES = list(Role)


def _expected_membership(actor: Role, target: Role | None, new: Role | None) -> bool:
    if actor is OW:
        return True
    if actor is AD:
        manageable = {ED, VI}
        return (target is None or target in manageable) and (new is None or new in manageable)
    return False


# (target_role, new_role): add = (None, role), change = (role, role), remove = (role, None).
OPERATIONS = [(target, new) for target in [None, *ROLES] for new in [None, *ROLES] if target or new]


@pytest.mark.parametrize("actor", ROLES)
@pytest.mark.parametrize(("target", "new"), OPERATIONS)
def test_membership_change_matrix(actor: Role, target: Role | None, new: Role | None) -> None:
    decision = decide_membership_change(actor, target_role=target, new_role=new)
    assert decision.allowed is _expected_membership(actor, target, new)
    assert decision.visible


@pytest.mark.parametrize(
    ("target", "new"),
    [(VI, AD), (ED, OW), (AD, VI), (OW, VI)],
)
def test_admin_cannot_escalate_or_touch_higher_roles(target: Role, new: Role) -> None:
    assert not decide_membership_change(AD, target_role=target, new_role=new).allowed


def test_non_member_cannot_change_memberships() -> None:
    decision = decide_membership_change(None, target_role=VI, new_role=ED)
    assert not decision.allowed
    assert not decision.visible
