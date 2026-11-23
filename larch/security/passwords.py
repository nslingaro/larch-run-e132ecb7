"""Argon2id password hashing. Salts come from the library's CSPRNG."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from larch.config import Settings


class Passwords:
    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # Verified against when an email has no account, so the response time does not
        # reveal whether the account exists.
        self._dummy_hash = self._hasher.hash("larch-timing-equaliser")

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str | None, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash or self._dummy_hash, password) and password_hash is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)
