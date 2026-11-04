"""Password hashing (apiguard.passwords)."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher, Type, extract_parameters

from apiguard import passwords


def test_production_hashes_are_argon2id_with_rfc9106_low_memory_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The suite swaps in cheap parameters (tests/conftest.py); restore the module's own.
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher())
    params = extract_parameters(passwords.hash_password("a long enough password"))
    assert params.type is Type.ID
    assert params.memory_cost >= 64 * 1024
    assert params.time_cost >= 3


def test_hash_and_verify() -> None:
    stored = passwords.hash_password("a long enough password")
    assert stored.startswith("$argon2id$")
    assert passwords.verify_password(stored, "a long enough password")
    assert not passwords.verify_password(stored, "a long enough passwore")


def test_hashes_are_salted() -> None:
    assert passwords.hash_password("same input here") != passwords.hash_password("same input here")


def test_verify_tolerates_malformed_hash() -> None:
    assert not passwords.verify_password("not-a-hash", "whatever")


def test_unknown_account_still_costs_one_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real_verify = passwords.verify_password

    def spy(password_hash: str, password: str) -> bool:
        calls.append(password_hash)
        return real_verify(password_hash, password)

    monkeypatch.setattr(passwords, "verify_password", spy)
    assert passwords.verify_login_password(None, "guess") is False
    assert calls == [passwords._DUMMY_HASH]

    stored = passwords.hash_password("a long enough password")
    calls.clear()
    assert passwords.verify_login_password(stored, "a long enough password") is True
    assert calls == [stored]


def test_needs_rehash_detects_weaker_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("pw")
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher())
    assert passwords.needs_rehash(weak)
