"""Validation of uploaded documents (FR-08).

The type is decided from the file's own signature ("magic bytes"). The declared
content type and the file name's extension must agree with it; neither is trusted alone.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata

MAX_DOCUMENT_BYTES = 10 * 1024 * 1024  # 10,485,760
MAX_DOCUMENTS_PER_APPLICATION = 10
MAX_FILENAME_LENGTH = 255

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
)
_EXTENSIONS = {
    "application/pdf": {".pdf"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
}
_DEFAULT_EXTENSION = {"application/pdf": ".pdf", "image/jpeg": ".jpg", "image/png": ".png"}


class UnsupportedFile(Exception):
    pass


def detect_content_type(head: bytes) -> str | None:
    for signature, content_type in _SIGNATURES:
        if head.startswith(signature):
            return content_type
    return None


def clean_filename(raw: str | None) -> str:
    """Keep only the final path component, drop control and format characters."""
    name = (raw or "").replace("\\", "/")
    name = posixpath.basename(name)
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    name = name.strip().strip(".")
    return name


def check_upload(data: bytes, declared_content_type: str | None, filename: str) -> tuple[str, str]:
    """Return the verified content type and file name, or raise UnsupportedFile.

    ``filename`` must already have been through clean_filename(); an empty name gets a
    generic one matching the detected type.
    """
    detected = detect_content_type(data[:16])
    if detected is None:
        raise UnsupportedFile("signature")
    declared = (declared_content_type or "").split(";")[0].strip().lower()
    if declared != detected:
        raise UnsupportedFile("declared type mismatch")
    if not filename:
        filename = "document" + _DEFAULT_EXTENSION[detected]
    extension = posixpath.splitext(filename.lower())[1]
    if extension not in _EXTENSIONS[detected]:
        raise UnsupportedFile("extension mismatch")
    return detected, filename


_ASCII_SAFE = re.compile(r"[^A-Za-z0-9._ ()\-]")


def content_disposition(filename: str) -> str:
    """RFC 6266 attachment header: an ASCII fallback plus the exact UTF-8 name."""
    from urllib.parse import quote

    fallback = _ASCII_SAFE.sub("_", unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode())
    fallback = fallback.strip() or "document"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"
