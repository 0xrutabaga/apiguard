"""The SQL listing filter and the per-object policy must agree for every member and document.

If ``visible_documents_clause`` and ``decide(..., DOCUMENT_READ, ...)`` ever diverged, a list
endpoint could leak documents that a direct GET would hide (or the reverse).
"""

from __future__ import annotations

import itertools

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.authz import document_resource, resolve_actor
from apiguard.models import Document, DocumentShare
from apiguard.policy import Action, decide, visible_documents_clause
from tests.support import World


def test_listing_filter_matches_per_object_decision(
    db: sessionmaker[Session], world: World
) -> None:
    members = ["a_owner", "a_admin", "a_editor", "a_editor2", "a_viewer", "b_owner", "outsider"]
    with db.begin() as session:
        # A document per member who can create one, plus shares of every kind.
        for i, name in enumerate(["a_owner", "a_admin", "a_editor2"]):
            session.add(
                Document(
                    org_id=world.org_a,
                    project_id=world.proj_a,
                    owner_id=world.uid(name),
                    title=f"doc {i}",
                    body="",
                )
            )
        session.flush()
        docs = session.execute(select(Document)).scalars().all()
        shares = itertools.cycle(["read", "edit", None])
        for doc in docs:
            if doc.org_id != world.org_a:
                continue
            for name in ("a_editor2", "a_viewer"):
                permission = next(shares)
                if permission and doc.owner_id != world.uid(name):
                    session.add(
                        DocumentShare(
                            document_id=doc.id,
                            user_id=world.uid(name),
                            org_id=world.org_a,
                            permission=permission,
                        )
                    )

    checked = 0
    with db() as session:
        docs = session.execute(select(Document)).scalars().all()
        for name, org in itertools.product(members, [world.org_a, world.org_b]):
            actor = resolve_actor(session, world.uid(name), org)
            listed = set(
                session.execute(
                    select(Document.id).where(visible_documents_clause(actor))
                ).scalars()
            )
            for doc in docs:
                allowed = decide(
                    actor, Action.DOCUMENT_READ, document_resource(session, actor, doc)
                ).allowed
                assert (doc.id in listed) is allowed, (name, org, doc.title)
                checked += 1
    assert checked == len(members) * 2 * len(docs)
