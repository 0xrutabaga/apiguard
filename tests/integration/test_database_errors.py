"""How database failures map to HTTP: integrity conflicts are 409, outages are 503."""

from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import DocumentShare
from tests.support import World


def _wait_until_blocked_on_a_lock(engine: Engine, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as conn:
            waiting = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE wait_event_type = 'Lock' AND datname = current_database()"
                )
            ).scalar_one()
        if waiting:
            return
        time.sleep(0.05)
    raise AssertionError("the request never blocked on the competing insert")


def test_losing_a_duplicate_share_race_returns_409(
    client: TestClient, world: World, db: sessionmaker[Session], engine: Engine
) -> None:
    """Deterministic race: another transaction inserts the same share and commits late.

    The request's existence check cannot see the uncommitted row, so it inserts too, blocks on
    the primary key, and fails with a unique violation once the other transaction commits.
    """
    competitor = db()
    competitor.add(
        DocumentShare(
            document_id=world.doc_a,
            user_id=world.uid("a_editor2"),
            org_id=world.org_a,
            permission="read",
        )
    )
    competitor.flush()  # row inserted and locked, not committed

    result: dict[str, object] = {}

    def request() -> None:
        response = client.put(
            f"{world.doc_a_url}/shares/{world.uid('a_editor2')}",
            json={"permission": "edit"},
            headers=world.auth("a_editor"),
        )
        result["status"] = response.status_code
        result["body"] = response.json()

    thread = threading.Thread(target=request)
    thread.start()
    try:
        _wait_until_blocked_on_a_lock(engine)
    finally:
        competitor.commit()
        competitor.close()
    thread.join(timeout=30)

    assert result == {"status": 409, "body": {"detail": "conflict"}}
