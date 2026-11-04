"""Happy paths and data invariants for organisations, projects, documents and shares."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import Document, DocumentShare, Membership
from tests.support import World


def test_create_org_makes_caller_owner(client: TestClient, world: World) -> None:
    headers = world.auth("outsider")
    org = client.post("/orgs", json={"name": "New"}, headers=headers)
    assert org.status_code == 201
    mine = client.get("/orgs", headers=headers).json()
    assert mine == [{"id": org.json()["id"], "name": "New", "role": "owner"}]
    detail = client.get(f"/orgs/{org.json()['id']}", headers=headers).json()
    assert detail["role"] == "owner"


def test_project_lifecycle(client: TestClient, world: World) -> None:
    headers = world.auth("a_admin")
    base = f"/orgs/{world.org_a}/projects"
    created = client.post(base, json={"name": "Roadmap"}, headers=headers)
    assert created.status_code == 201
    pid = created.json()["id"]
    assert (
        client.patch(f"{base}/{pid}", json={"name": "Plan"}, headers=headers).json()["name"]
        == "Plan"
    )
    names = [p["name"] for p in client.get(base, headers=world.auth("a_viewer")).json()]
    assert "Plan" in names
    assert client.delete(f"{base}/{pid}", headers=headers).status_code == 204
    assert client.get(f"{base}/{pid}", headers=headers).status_code == 404


def test_project_pagination(client: TestClient, world: World) -> None:
    base = f"/orgs/{world.org_a}/projects"
    headers = world.auth("a_owner")
    first = client.get(f"{base}?limit=1", headers=headers).json()
    second = client.get(f"{base}?limit=1&offset=1", headers=headers).json()
    assert len(first) == len(second) == 1
    assert first[0]["id"] != second[0]["id"]


def test_document_lifecycle_by_editor(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    headers = world.auth("a_editor2")
    base = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    created = client.post(base, json={"title": "Draft", "body": "v1"}, headers=headers)
    assert created.status_code == 201
    url = f"{base}/{created.json()['id']}"
    updated = client.patch(url, json={"body": "v2"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["body"] == "v2"
    assert updated.json()["title"] == "Draft"
    assert updated.json()["updated_at"] >= created.json()["updated_at"]
    assert client.patch(url, json={}, headers=headers).status_code == 422
    assert client.delete(url, headers=headers).status_code == 204
    with db() as session:
        assert session.get(Document, created.json()["id"]) is None


def test_managers_see_every_document_and_members_see_own_and_shared(
    client: TestClient, world: World
) -> None:
    base = f"/orgs/{world.org_a}/projects/{world.proj_a}/documents"
    client.post(base, json={"title": "editor2's"}, headers=world.auth("a_editor2"))

    def titles(name: str) -> set[str]:
        return {d["title"] for d in client.get(base, headers=world.auth(name)).json()}

    assert titles("a_owner") == titles("a_admin") == {"A plan", "editor2's"}
    assert titles("a_editor") == {"A plan"}
    assert titles("a_editor2") == {"editor2's"}
    assert titles("a_viewer") == set()

    client.put(
        f"{world.doc_a_url}/shares/{world.uid('a_viewer')}",
        json={"permission": "read"},
        headers=world.auth("a_editor"),
    )
    assert titles("a_viewer") == {"A plan"}


def test_share_upsert_changes_permission(client: TestClient, world: World) -> None:
    url = f"{world.doc_a_url}/shares/{world.uid('a_editor2')}"
    owner = world.auth("a_editor")
    assert (
        client.put(url, json={"permission": "read"}, headers=owner).json()["permission"] == "read"
    )
    editor2 = world.auth("a_editor2")
    assert client.patch(world.doc_a_url, json={"body": "x"}, headers=editor2).status_code == 403
    assert (
        client.put(url, json={"permission": "edit"}, headers=owner).json()["permission"] == "edit"
    )
    assert client.patch(world.doc_a_url, json={"body": "x"}, headers=editor2).status_code == 200


def test_unshare_missing_share_is_404(client: TestClient, world: World) -> None:
    url = f"{world.doc_a_url}/shares/{world.uid('a_viewer')}"
    assert client.delete(url, headers=world.auth("a_editor")).status_code == 404


def test_removing_a_member_deletes_their_shares(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.put(
        f"{world.doc_a_url}/shares/{world.uid('a_viewer')}",
        json={"permission": "read"},
        headers=world.auth("a_editor"),
    )
    client.delete(
        f"/orgs/{world.org_a}/members/{world.uid('a_viewer')}", headers=world.auth("a_admin")
    )
    with db() as session:
        assert session.execute(select(DocumentShare)).first() is None


def test_deleting_a_project_deletes_its_documents(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    response = client.delete(
        f"/orgs/{world.org_a}/projects/{world.proj_a}", headers=world.auth("a_owner")
    )
    assert response.status_code == 204
    with db() as session:
        assert session.get(Document, world.doc_a) is None
        assert session.get(Document, world.doc_b) is not None


def test_member_management(client: TestClient, world: World, db: sessionmaker[Session]) -> None:
    members = f"/orgs/{world.org_a}/members"
    owner = world.auth("a_owner")
    added = client.post(
        members, json={"email": "outsider@example.com", "role": "viewer"}, headers=owner
    )
    assert added.status_code == 201
    again = client.post(
        members, json={"email": "outsider@example.com", "role": "viewer"}, headers=owner
    )
    assert again.status_code == 409
    unknown = client.post(
        members, json={"email": "ghost@example.com", "role": "viewer"}, headers=owner
    )
    assert unknown.status_code == 404
    promoted = client.patch(
        f"{members}/{world.uid('outsider')}", json={"role": "admin"}, headers=owner
    )
    assert promoted.json()["role"] == "admin"
    assert client.get(f"/orgs/{world.org_a}", headers=world.auth("outsider")).status_code == 200


def test_last_owner_cannot_leave_or_be_demoted(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    url = f"/orgs/{world.org_a}/members/{world.uid('a_owner')}"
    owner = world.auth("a_owner")
    assert client.patch(url, json={"role": "admin"}, headers=owner).status_code == 409
    assert client.delete(url, headers=owner).status_code == 409
    # With a second owner, the first may step down.
    client.patch(
        f"/orgs/{world.org_a}/members/{world.uid('a_admin')}", json={"role": "owner"}, headers=owner
    )
    assert client.patch(url, json={"role": "admin"}, headers=owner).status_code == 200
    with db() as session:
        roles = session.execute(
            select(Membership.role).where(
                Membership.org_id == world.org_a, Membership.role == "owner"
            )
        ).all()
    assert len(roles) == 1
