"""Operator commands: ``python -m larch <command>``.

create-admin <email> <full-name>
    Creates an admin account (FR-20). Prompts for the password twice, or reads one line
    from standard input when that is not a terminal. Exit codes: 0 created, 1 the email
    already has an account, 2 invalid input.
purge-expired
    Deletes closed applications and their documents once the retention period has passed
    . Refuses to run until LARCH_RETENTION_DAYS_AFTER_CLOSURE is set,
    because the retention period is still an open question (product spec, question 1).
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import timedelta
from typing import TextIO

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from larch import models
from larch.config import Settings
from larch.db import create_db_engine, create_schema, make_sessionmaker, utcnow
from larch.logs import configure_logging, security_event
from larch.models import ApplicationStatus, Role
from larch.schemas import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, Email, Name
from larch.security.passwords import Passwords
from larch.storage import DocumentStore, StorageError

EXIT_OK, EXIT_EXISTS, EXIT_INVALID = 0, 1, 2


def _read_password(stdin: TextIO, stderr: TextIO) -> str | None:
    if stdin.isatty():
        first = getpass.getpass("Password: ")
        second = getpass.getpass("Repeat password: ")
        if first != second:
            print("Passwords do not match.", file=stderr)
            return None
        return first
    line = stdin.readline()
    return line.rstrip("\r\n")


def create_admin(email: str, full_name: str, settings: Settings, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    for label, adapter, value in (("email", TypeAdapter(Email), email), ("full name", TypeAdapter(Name), full_name)):
        try:
            adapter.validate_python(value)
        except ValidationError as exc:
            print(f"Invalid {label}: {exc.errors()[0]['msg']}", file=stderr)
            return EXIT_INVALID
    email = TypeAdapter(Email).validate_python(email)
    full_name = TypeAdapter(Name).validate_python(full_name)

    password = _read_password(stdin, stderr)
    if password is None:
        return EXIT_INVALID
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        print(f"The password must be {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters.", file=stderr)
        return EXIT_INVALID

    engine = create_db_engine(settings)
    try:
        create_schema(engine)
        sessions = make_sessionmaker(engine)
        with sessions() as db:
            email_key = email.lower()
            if db.scalar(select(models.User.id).where(models.User.email_key == email_key)):
                print("An account with this email already exists.", file=stderr)
                return EXIT_EXISTS
            admin = models.User(
                email=email,
                email_key=email_key,
                password_hash=Passwords(settings).hash(password),
                full_name=full_name,
                role=Role.ADMIN.value,
                active=True,
                created_at=utcnow(),
            )
            db.add(admin)
            try:
                db.commit()
            except IntegrityError:
                print("An account with this email already exists.", file=stderr)
                return EXIT_EXISTS
            security_event("admin_created", "success", actor_role="operator", target_type="user", target_id=admin.id)
            print(f"Created admin account {admin.id}.", file=stdout)
            return EXIT_OK
    finally:
        engine.dispose()


def purge_expired(settings: Settings, stdout: TextIO, stderr: TextIO) -> int:
    days = settings.retention_days_after_closure
    if days is None:
        print(
            "The retention period has not been decided (product spec, open question 1). "
            "Set LARCH_RETENTION_DAYS_AFTER_CLOSURE once Legal approves it. Nothing was deleted.",
            file=stderr,
        )
        return EXIT_INVALID

    cutoff = utcnow() - timedelta(days=days)
    engine = create_db_engine(settings)
    store = DocumentStore(settings.documents_dir)
    A, D = models.Application, models.Document
    closed_at = func.coalesce(A.decided_at, A.withdrawn_at)
    applications = documents = 0
    try:
        create_schema(engine)
        with make_sessionmaker(engine)() as db:
            expired = db.scalars(
                select(A.id).where(
                    A.status.in_(
                        [ApplicationStatus.APPROVED.value, ApplicationStatus.REJECTED.value,
                         ApplicationStatus.WITHDRAWN.value]
                    ),
                    closed_at < cutoff,
                    A.legal_hold.is_(False),
                )
            ).all()
            for application_id in expired:
                keys = db.scalars(select(D.storage_key).where(D.application_id == application_id)).all()
                db.execute(delete(D).where(D.application_id == application_id))
                db.execute(delete(A).where(A.id == application_id))
                db.commit()  # wrapped data keys are gone: the files are crypto-erased from here
                for key in keys:
                    try:
                        store.delete(key)
                    except StorageError:
                        security_event("retention_file_delete_failed", "failure", target_type="application",
                                       target_id=application_id)
                applications += 1
                documents += len(keys)
            db.execute(delete(models.Session).where(models.Session.expires_at < utcnow()))
            db.commit()
    finally:
        engine.dispose()
    security_event("retention_purge", "success", count=applications)
    print(f"Deleted {applications} application(s) and {documents} document(s).", file=stdout)
    return EXIT_OK


def main(argv: list[str] | None = None, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout,
         stderr: TextIO = sys.stderr, settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m larch")
    commands = parser.add_subparsers(dest="command", required=True)
    admin_cmd = commands.add_parser("create-admin", help="create an admin account")
    admin_cmd.add_argument("email")
    admin_cmd.add_argument("full_name", metavar="full-name")
    commands.add_parser("purge-expired", help="delete applications past the retention period")
    args = parser.parse_args(argv)

    settings = settings or Settings()
    configure_logging(settings.environment.value)
    if args.command == "create-admin":
        return create_admin(args.email, args.full_name, settings, stdin, stdout, stderr)
    return purge_expired(settings, stdout, stderr)
