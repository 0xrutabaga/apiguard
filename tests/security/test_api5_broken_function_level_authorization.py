"""OWASP API5:2023 Broken Function Level Authorization.

Members who can see an organisation must still be refused functions above their role (403),
and admins must not be able to escalate themselves or others.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import AuditEvent, Membership
from tests.support import World


def _role(db: sessionmaker[Session], world: World, name: str) -> str | None:
    with db() as session:
        membership = session.get(Membership, (world.org_a, world.uid(name)))
        return membership.role if membership else None


@pytest.mark.parametrize("actor", ["a_editor", "a_viewer"])
def test_non_managers_cannot_manage_projects(client: TestClient, world: World, actor: str) -> None:
    headers = world.auth(actor)
    base = f"/orgs/{world.org_a}/projects"
    assert client.post(base, json={"name": "p"}, headers=headers).status_code == 403
    assert (
        client.patch(f"{base}/{world.proj_a}", json={"name": "p"}, headers=headers).status_code
        == 403
    )
    assert client.delete(f"{base}/{world.proj_a}", headers=headers).status_code == 403


def test_viewer_cannot_create_documents(client: TestClient, world: World) -> None:
    url = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    assert client.post(url, json={"title": "t"}, headers=world.auth("a_viewer")).status_code == 403


def test_viewer_with_read_share_cannot_edit(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    share = f"{world.doc_a_url}/shares/{world.uid('a_viewer')}"
    client.put(share, json={"permission": "read"}, headers=world.auth("a_editor"))
    viewer = world.auth("a_viewer")
    assert client.get(world.doc_a_url, headers=viewer).status_code == 200
    response = client.patch(world.doc_a_url, json={"body": "edited"}, headers=viewer)
    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}


def test_edit_share_cannot_lift_viewer_above_role_ceiling(client: TestClient, world: World) -> None:
    share = f"{world.doc_a_url}/shares/{world.uid('a_viewer')}"
    assert (
        client.put(share, json={"permission": "edit"}, headers=world.auth("a_editor")).status_code
        == 200
    )
    response = client.patch(world.doc_a_url, json={"body": "x"}, headers=world.auth("a_viewer"))
    assert response.status_code == 403


def test_demotion_narrows_existing_share_immediately(client: TestClient, world: World) -> None:
    share = f"{world.doc_a_url}/shares/{world.uid('a_editor2')}"
    client.put(share, json={"permission": "edit"}, headers=world.auth("a_editor"))
    editor2 = world.auth("a_editor2")  # issued before the demotion
    assert client.patch(world.doc_a_url, json={"body": "v2"}, headers=editor2).status_code == 200
    demote = client.patch(
        f"/orgs/{world.org_a}/members/{world.uid('a_editor2')}",
        json={"role": "viewer"},
        headers=world.auth("a_admin"),
    )
    assert demote.status_code == 200
    assert client.patch(world.doc_a_url, json={"body": "v3"}, headers=editor2).status_code == 403


def test_edit_share_does_not_allow_delete_or_reshare(client: TestClient, world: World) -> None:
    client.put(
        f"{world.doc_a_url}/shares/{world.uid('a_editor2')}",
        json={"permission": "edit"},
        headers=world.auth("a_editor"),
    )
    editor2 = world.auth("a_editor2")
    assert client.delete(world.doc_a_url, headers=editor2).status_code == 403
    reshare = client.put(
        f"{world.doc_a_url}/shares/{world.uid('a_viewer')}",
        json={"permission": "read"},
        headers=editor2,
    )
    assert reshare.status_code == 403


@pytest.mark.parametrize("actor", ["a_editor", "a_viewer"])
def test_non_managers_cannot_manage_members(
    client: TestClient, world: World, db: sessionmaker[Session], actor: str
) -> None:
    headers = world.auth(actor)
    members = f"/orgs/{world.org_a}/members"
    add = client.post(
        members, json={"email": "outsider@example.com", "role": "viewer"}, headers=headers
    )
    assert add.status_code == 403
    promote = client.patch(f"{members}/{world.uid(actor)}", json={"role": "owner"}, headers=headers)
    assert promote.status_code == 403
    remove = client.delete(f"{members}/{world.uid('a_admin')}", headers=headers)
    assert remove.status_code == 403
    assert _role(db, world, actor) in {"editor", "viewer"}
    assert _role(db, world, "a_admin") == "admin"


@pytest.mark.parametrize("new_role", ["admin", "owner"])
def test_admin_cannot_escalate_self(
    client: TestClient, world: World, db: sessionmaker[Session], new_role: str
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_admin')}"
    response = client.patch(url, json={"role": new_role}, headers=world.auth("a_admin"))
    assert response.status_code == 403
    assert _role(db, world, "a_admin") == "admin"


@pytest.mark.parametrize("new_role", ["admin", "owner"])
def test_admin_cannot_grant_admin_or_owner(
    client: TestClient, world: World, db: sessionmaker[Session], new_role: str
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_viewer')}"
    response = client.patch(url, json={"role": new_role}, headers=world.auth("a_admin"))
    assert response.status_code == 403
    assert _role(db, world, "a_viewer") == "viewer"
    add = client.post(
        f"/orgs/{world.org_a}/members",
        json={"email": "outsider@example.com", "role": new_role},
        headers=world.auth("a_admin"),
    )
    assert add.status_code == 403


def test_admin_cannot_demote_or_remove_owner(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_owner')}"
    headers = world.auth("a_admin")
    assert client.patch(url, json={"role": "viewer"}, headers=headers).status_code == 403
    assert client.delete(url, headers=headers).status_code == 403
    assert _role(db, world, "a_owner") == "owner"


def test_admin_can_manage_editors_and_viewers(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_viewer')}"
    assert (
        client.patch(url, json={"role": "editor"}, headers=world.auth("a_admin")).status_code == 200
    )
    assert _role(db, world, "a_viewer") == "editor"


@pytest.mark.parametrize("actor", ["a_editor", "a_viewer"])
def test_non_managers_cannot_read_the_audit_log(
    client: TestClient, world: World, actor: str
) -> None:
    url = f"/orgs/{world.org_a}/audit-events"
    assert client.get(url, headers=world.auth(actor)).status_code == 403


def test_denials_are_audited_with_the_request_id(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    response = client.post(
        f"/orgs/{world.org_a}/projects",
        json={"name": "p"},
        headers={**world.auth("a_viewer"), "X-Request-ID": "bfla-test-1"},
    )
    assert response.status_code == 403
    assert response.headers["x-request-id"] == "bfla-test-1"
    with db() as session:
        event = session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "permission_denied")
        ).scalar_one()
    assert event.request_id == "bfla-test-1"
    assert event.actor_user_id == world.uid("a_viewer")
    assert event.detail["action"] == "project.create"
    assert event.detail["status"] == 403
