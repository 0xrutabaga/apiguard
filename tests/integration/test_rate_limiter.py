"""apiguard.ratelimit.RateLimiter against PostgreSQL with a controllable clock."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apiguard.models import RateLimitCounter
from apiguard.ratelimit import Limit, RateLimiter, RateLimitExceeded


class FakeClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_window_resets_and_retry_after_counts_down(db: sessionmaker[Session]) -> None:
    clock = FakeClock(999_960.0)  # a multiple of 60, so exactly the start of a window
    limiter = RateLimiter(db, window_seconds=60, clock=clock)
    limit = Limit("k", max_attempts=2)
    limiter.hit(limit)
    limiter.hit(limit)

    clock.now += 15
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.hit(limit)
    assert exc.value.retry_after == 45

    clock.now += 45  # next window
    limiter.hit(limit)


def test_old_windows_are_cleaned_up(db: sessionmaker[Session]) -> None:
    clock = FakeClock(999_960.0)
    limiter = RateLimiter(db, window_seconds=60, clock=clock)
    for _ in range(3):
        limiter.hit(Limit("k", 100))
        clock.now += 60
    with db() as session:
        rows = session.execute(select(RateLimitCounter)).scalars().all()
    assert len(rows) == 1


def test_hit_all_counts_every_limit_before_raising(db: sessionmaker[Session]) -> None:
    limiter = RateLimiter(db, window_seconds=60, clock=FakeClock(999_960.0))
    tight, loose = Limit("tight", 1), Limit("loose", 100)
    limiter.hit_all([tight, loose])
    with pytest.raises(RateLimitExceeded):
        limiter.hit_all([tight, loose])
    with db() as session:
        rows = session.execute(select(RateLimitCounter.key, RateLimitCounter.count)).all()
    counts = {key: count for key, count in rows}
    assert counts == {"tight": 2, "loose": 2}


def test_concurrent_hits_are_counted_exactly(db: sessionmaker[Session]) -> None:
    """The upsert is atomic, so N parallel attempts produce a count of exactly N."""
    limiter = RateLimiter(db, window_seconds=3600, clock=FakeClock(999_960.0))
    limit = Limit("parallel", max_attempts=5)
    outcomes: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def attempt() -> None:
        barrier.wait()
        try:
            limiter.hit(limit)
            ok = True
        except RateLimitExceeded:
            ok = False
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert outcomes.count(True) == 5
    assert outcomes.count(False) == 15


def test_finished_windows_of_other_keys_are_pruned_too(db: sessionmaker[Session]) -> None:
    """New keys (fresh emails, IPs) must not accumulate: every hit prunes all old windows."""
    clock = FakeClock(999_960.0)
    limiter = RateLimiter(db, window_seconds=60, clock=clock)
    for i in range(50):
        limiter.hit(Limit(f"login:acct:{i}", 100))
    clock.now += 60
    limiter.hit(Limit("login:acct:new", 100))
    with db() as session:
        keys = session.execute(select(RateLimitCounter.key)).scalars().all()
    assert keys == ["login:acct:new"]


def test_only_the_first_rejection_in_a_window_is_flagged(db: sessionmaker[Session]) -> None:
    limiter = RateLimiter(db, window_seconds=60, clock=FakeClock(999_960.0))
    limit = Limit("k", 1)
    limiter.hit(limit)
    flags = []
    for _ in range(3):
        with pytest.raises(RateLimitExceeded) as exc:
            limiter.hit(limit)
        flags.append(exc.value.first_in_window)
    assert flags == [True, False, False]
