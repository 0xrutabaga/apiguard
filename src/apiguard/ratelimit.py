"""Fixed-window rate limiting stored in PostgreSQL.

Each call to ``hit`` atomically increments the counter for ``(key, window)`` with
``INSERT ... ON CONFLICT DO UPDATE ... RETURNING count`` in its own transaction, so the limit
holds across several API processes and the increment persists even when the request that
triggered it fails afterwards (for example a login with a wrong password).

Policy (documented in docs/THREAT_MODEL.md): this is throttling, not a permanent lockout.
When an account or IP exceeds its limit, further attempts get 429 with ``Retry-After`` until
the current window ends; nothing has to be unlocked by an administrator.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import RateLimitCounter


class RateLimitExceeded(Exception):
    def __init__(self, key: str, retry_after: int) -> None:
        super().__init__(key)
        self.key = key
        self.retry_after = retry_after


@dataclass(frozen=True)
class Limit:
    key: str
    max_attempts: int


def account_key(prefix: str, identifier: str) -> str:
    """Key for a per-account limit. Identifiers (emails) are hashed so they are not stored."""
    digest = hashlib.sha256(identifier.strip().lower().encode()).hexdigest()
    return f"{prefix}:acct:{digest}"


def ip_key(prefix: str, client_ip: str) -> str:
    return f"{prefix}:ip:{client_ip}"


class RateLimiter:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        window_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._session_factory = session_factory
        self._window = window_seconds
        self._clock = clock

    def hit(self, limit: Limit) -> None:
        """Count one attempt against ``limit``; raise RateLimitExceeded if it is over."""
        now = self._clock()
        window_start = int(now // self._window) * self._window
        stmt = (
            insert(RateLimitCounter)
            .values(key=limit.key, window_start=window_start, count=1)
            .on_conflict_do_update(
                index_elements=[RateLimitCounter.key, RateLimitCounter.window_start],
                set_={"count": RateLimitCounter.count + 1},
            )
            .returning(RateLimitCounter.count)
        )
        with self._session_factory.begin() as session:
            count = session.execute(stmt).scalar_one()
            # Opportunistic cleanup of this key's finished windows keeps the table small.
            session.execute(
                delete(RateLimitCounter).where(
                    RateLimitCounter.key == limit.key,
                    RateLimitCounter.window_start < window_start,
                )
            )
        if count > limit.max_attempts:
            retry_after = max(1, math.ceil(window_start + self._window - now))
            raise RateLimitExceeded(limit.key, retry_after)

    def hit_all(self, limits: list[Limit]) -> None:
        """Count the attempt against every limit, then raise for the first exceeded one.

        Every counter is incremented before raising so that an attacker who is already over
        the per-IP limit still consumes per-account budget, and vice versa.
        """
        exceeded: RateLimitExceeded | None = None
        for limit in limits:
            try:
                self.hit(limit)
            except RateLimitExceeded as exc:
                if exceeded is None or exc.retry_after > exceeded.retry_after:
                    exceeded = exc
        if exceeded is not None:
            raise exceeded
