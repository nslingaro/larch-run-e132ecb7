"""File store for encrypted documents under LARCH_DOCUMENTS_DIR.

Storage keys are generated here from a CSPRNG and never derived from client input.
Every path is resolved beneath the configured root and symlinks are refused.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

_STORAGE_KEY = re.compile(r"^[0-9a-f]{2}/[0-9a-f]{32}$")


class StorageError(Exception):
    pass


class DocumentStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root).resolve()

    @property
    def root(self) -> Path:
        return self._root

    def ensure_root(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @staticmethod
    def new_key() -> str:
        name = secrets.token_hex(16)
        return f"{name[:2]}/{name}"

    def _path(self, key: str) -> Path:
        if not _STORAGE_KEY.fullmatch(key):
            raise StorageError("invalid storage key")
        path = (self._root / key).resolve()
        if not path.is_relative_to(self._root):
            raise StorageError("storage key escapes the document root")
        return path

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        directory = path.parent
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.resolve() != directory:
            raise StorageError("document directory is a symlink")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise StorageError("could not create document file") from exc
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise StorageError("could not write document file") from exc

    def get(self, key: str) -> bytes:
        path = self._path(key)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise StorageError("could not open document file") from exc
        with os.fdopen(fd, "rb") as handle:
            return handle.read()

    def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise StorageError("could not delete document file") from exc
