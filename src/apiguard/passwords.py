"""Password hashing with Argon2id (argon2-cffi).

``verify_login_password`` always performs one Argon2 verification, even when the account does
not exist, so the response time of a failed login does not reveal whether the email is
registered.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# argon2-cffi defaults follow the RFC 9106 low-memory profile (Argon2id, t=3, m=64 MiB, p=4).
_hasher = PasswordHasher()

# Hash of a random value nobody knows; verifying against it costs the same as a real check.
_DUMMY_HASH = _hasher.hash("apiguard-dummy-password-for-timing-equalisation")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_login_password(password_hash: str | None, password: str) -> bool:
    """Verify a login attempt; ``password_hash`` is None when the account does not exist."""
    if password_hash is None:
        verify_password(_DUMMY_HASH, password)
        return False
    return verify_password(password_hash, password)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
