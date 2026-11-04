"""Audit log contents, access control and the append-only guarantee."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import AuditEvent
from tests.support import TEST_PASSWORD, World


def _events(db: sessionmaker[Session], event_type: str) -> list[AuditEvent]:
    with db() as session:
        return list(
            session.execute(
                select(AuditEvent)
                .where(AuditEvent.event_type == event_type)
                .order_by(AuditEvent.id)
            ).scalars()
        )


def test_login_success_and_failure_are_recorded_with_request_id(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    ok = client.post(
        "/auth/login",
        json={"email": "a_owner@example.com", "password": TEST_PASSWORD},
        headers={"X-Request-ID": "req-ok"},
    )
    bad = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "nope"},
        headers={"X-Request-ID": "req-bad"},
    )
    assert ok.status_code == 200 and bad.status_code == 401
    [succeeded] = _events(db, "login_succeeded")
    [failed] = _events(db, "login_failed")
    assert succeeded.actor_user_id == world.uid("a_owner")
    assert succeeded.request_id == "req-ok"
    assert failed.actor_user_id is None
    assert failed.request_id == "req-bad"
    assert failed.client_ip == "testclient"


def test_cross_tenant_probe_is_recorded_as_404_denial(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.get(world.doc_a_url, headers=world.auth("b_owner"))
    [event] = _events(db, "permission_denied")
    assert event.actor_user_id == world.uid("b_owner")
    assert event.org_id == world.org_a
    assert event.detail["status"] == 404


def test_role_change_is_recorded_in_the_same_transaction(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.patch(
        f"/orgs/{world.org_a}/members/{world.uid('a_viewer')}",
        json={"role": "editor"},
        headers=world.auth("a_owner"),
    )
    [event] = _events(db, "role_changed")
    assert event.detail == {"user_id": str(world.uid("a_viewer")), "from": "viewer", "to": "editor"}
    assert event.org_id == world.org_a


def test_rejected_role_change_leaves_no_role_changed_event(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.patch(
        f"/orgs/{world.org_a}/members/{world.uid('a_owner')}",
        json={"role": "admin"},
        headers=world.auth("a_owner"),
    )  # last owner: 409
    assert _events(db, "role_changed") == []


def test_org_audit_endpoint_is_scoped_to_the_org(
    client: TestClient, world: World, db: sessionmaker[Session]
) -> None:
    client.get(world.doc_b_url, headers=world.auth("a_owner"))  # denial recorded against org B
    client.post(f"/orgs/{world.org_a}/projects", json={"name": "p"}, headers=world.auth("a_viewer"))
    a_events = client.get(f"/orgs/{world.org_a}/audit-events", headers=world.auth("a_admin")).json()
    assert a_events and all(e["org_id"] == str(world.org_a) for e in a_events)
    b_events = client.get(
        f"/orgs/{world.org_b}/audit-events?event_type=permission_denied",
        headers=world.auth("b_owner"),
    ).json()
    assert [e["actor_user_id"] for e in b_events] == [str(world.uid("a_owner"))]


def test_me_audit_events_show_only_own_events(client: TestClient, world: World) -> None:
    client.post("/auth/login", json={"email": "a_viewer@example.com", "password": "wrong"})
    client.post("/auth/login", json={"email": "a_owner@example.com", "password": "wrong"})
    events = client.get("/me/audit-events", headers=world.auth("a_viewer")).json()
    assert [e["event_type"] for e in events] == ["login_failed"]
    assert all(e["actor_user_id"] == str(world.uid("a_viewer")) for e in events)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET event_type = 'tampered'",
        "DELETE FROM audit_events",
    ],
)
def test_audit_events_are_append_only(
    client: TestClient, world: World, db: sessionmaker[Session], statement: str
) -> None:
    client.post("/auth/login", json={"email": "a_owner@example.com", "password": "wrong"})
    with pytest.raises(DBAPIError, match="append-only"), db.begin() as session:
        session.execute(text(statement))
    assert len(_events(db, "login_failed")) == 1
