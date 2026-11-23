"""Database engine, sessions and shared column types.

All queries go through SQLAlchemy expressions with bound parameters.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Engine, String, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from larch.config import Settings


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator[datetime]):
    """Stores naive UTC, returns timezone-aware UTC on every backend (SQLite included)."""

    impl = DateTime(timezone=False)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not accepted; use UTC-aware values")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: UTCDateTime(), str: String()}


def create_db_engine(settings: Settings) -> Engine:
    url = settings.database_url
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 15})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(
        url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "options": f"-c statement_timeout={settings.database_statement_timeout_ms}",
            "connect_timeout": 10,
        },
    )


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def create_schema(engine: Engine) -> None:
    # Version 1 creates the schema at startup; migrations arrive with the first change.
    from larch import models  # noqa: F401  (registers the tables)

    Base.metadata.create_all(engine)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
    finally:
        session.close()
