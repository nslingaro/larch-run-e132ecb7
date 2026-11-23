"""Envelope encryption for stored documents.

Each file gets its own random 256-bit data key and is encrypted with AES-256-GCM. The
data key is wrapped (AES-256-GCM) by a key-encryption key (KEK) injected from the secret
store and stored, wrapped, in the document's database row. Deleting that row therefore
also crypto-erases the file. The document's storage key is bound in as associated data,
so a file cannot be swapped for another document's file.

Rotation: add a new "<id>:<key>" entry to LARCH_DOCUMENT_ENCRYPTION_KEYS and point
LARCH_DOCUMENT_ENCRYPTION_ACTIVE_KEY_ID at it. Older keys stay listed to decrypt older
documents until they are re-wrapped.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
_KEY_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class DecryptionError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedBlob:
    key_id: str
    wrapped_data_key: bytes
    ciphertext: bytes


def parse_keyring(spec: str) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for entry in (part.strip() for part in spec.split(",")):
        if not entry:
            continue
        key_id, sep, encoded = entry.partition(":")
        if not sep or not _KEY_ID.match(key_id):
            raise ValueError("document encryption keys must look like '<key-id>:<base64 key>'")
        try:
            key = base64.b64decode(encoded, validate=True)
        except binascii.Error:
            raise ValueError(f"document encryption key {key_id!r} is not valid base64") from None
        if len(key) != 32:
            raise ValueError(f"document encryption key {key_id!r} must be 32 bytes (AES-256)")
        keys[key_id] = key
    if not keys:
        raise ValueError("no document encryption keys configured")
    return keys


class DocumentCipher:
    def __init__(self, keyring: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keyring:
            raise ValueError("the active document encryption key id is not in the keyring")
        self._keyring = keyring
        self._active = active_key_id

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> EncryptedBlob:
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = nonce + AESGCM(data_key).encrypt(nonce, plaintext, associated_data)
        wrap_nonce = os.urandom(NONCE_BYTES)
        kek = AESGCM(self._keyring[self._active])
        wrapped = wrap_nonce + kek.encrypt(wrap_nonce, data_key, b"larch-dek:" + associated_data)
        return EncryptedBlob(key_id=self._active, wrapped_data_key=wrapped, ciphertext=ciphertext)

    def decrypt(self, key_id: str, wrapped_data_key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        kek_bytes = self._keyring.get(key_id)
        if kek_bytes is None:
            raise DecryptionError("unknown key id")
        try:
            data_key = AESGCM(kek_bytes).decrypt(
                wrapped_data_key[:NONCE_BYTES], wrapped_data_key[NONCE_BYTES:], b"larch-dek:" + associated_data
            )
            return AESGCM(data_key).decrypt(ciphertext[:NONCE_BYTES], ciphertext[NONCE_BYTES:], associated_data)
        except (InvalidTag, ValueError):
            raise DecryptionError("authentication failed") from None


def generate_key_b64() -> str:
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()
