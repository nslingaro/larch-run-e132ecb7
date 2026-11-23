"""Wires configuration into the long-lived objects the request handlers use."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from larch.config import Settings
from larch.db import create_db_engine, make_sessionmaker
from larch.ratelimit import RateLimiter
from larch.security.document_crypto import DocumentCipher, generate_key_b64, parse_keyring
from larch.security.passwords import Passwords
from larch.security.tokens import TokenService, generate_signing_key_pem
from larch.storage import DocumentStore

logger = logging.getLogger("larch.startup")

DEV_DOCUMENT_KEY_ID = "dev"


@dataclass
class Services:
    settings: Settings
    engine: Engine
    sessions: sessionmaker[Session]
    passwords: Passwords
    tokens: TokenService
    cipher: DocumentCipher
    store: DocumentStore
    limiter: RateLimiter


def _dev_secret(path: Path, generate) -> str:
    """Development only: keep a generated secret under ./var so restarts keep working."""
    if path.exists():
        return path.read_text()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)
    logger.warning("generated a development-only secret", extra={"fields": {"event": "dev_secret_generated"}})
    return value


def build_services(settings: Settings) -> Services:
    dev_dir = Path(settings.documents_dir).resolve().parent / "dev-secrets"

    if settings.token_signing_key is not None:
        signing_key = settings.token_signing_key.get_secret_value()
    elif settings.is_development:
        signing_key = _dev_secret(dev_dir / "token-signing-key.pem", generate_signing_key_pem)
    else:  # Settings validation already refuses this; kept as a fail-closed guard.
        raise RuntimeError("LARCH_TOKEN_SIGNING_KEY is required")

    if settings.document_encryption_keys is not None:
        keyring = parse_keyring(settings.document_encryption_keys.get_secret_value())
        active = settings.document_encryption_active_key_id or ""
    elif settings.is_development:
        key = _dev_secret(dev_dir / "document-key.b64", generate_key_b64)
        keyring = parse_keyring(f"{DEV_DOCUMENT_KEY_ID}:{key.strip()}")
        active = DEV_DOCUMENT_KEY_ID
    else:
        raise RuntimeError("LARCH_DOCUMENT_ENCRYPTION_KEYS is required")

    previous = settings.token_previous_public_keys
    engine = create_db_engine(settings)
    return Services(
        settings=settings,
        engine=engine,
        sessions=make_sessionmaker(engine),
        passwords=Passwords(settings),
        tokens=TokenService(
            signing_key_pem=signing_key,
            previous_public_keys_pem=previous.get_secret_value() if previous else None,
            issuer=settings.token_issuer,
            audience=settings.token_audience,
            ttl=timedelta(minutes=settings.access_token_ttl_minutes),
        ),
        cipher=DocumentCipher(keyring, active),
        store=DocumentStore(settings.documents_dir),
        limiter=RateLimiter(settings.rate_limits),
    )
