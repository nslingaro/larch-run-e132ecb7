"""Operator commands: create-admin (FR-20) and purge-expired (retention placeholder)."""

from __future__ import annotations

import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from larch import models
from larch.app import create_app
from larch.cli import main
from larch.db import utcnow
from tests.conftest import API, PASSWORD, Api, bearer, make_settings


class _Stdin(io.StringIO):
    def isatty(self) -> bool:
        return False


def run(settings, *args: str, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), stdin=_Stdin(stdin), stdout=out, stderr=err, settings=settings)
    return code, out.getvalue(), err.getvalue()


def test_create_admin_from_standard_input(tmp_path):
    settings = make_settings(tmp_path)
    code, out, _ = run(settings, "create-admin", "Head@Larch.example", "Jo Head", stdin=PASSWORD + "\n")
    assert code == 0 and "Created admin account" in out
    with TestClient(create_app(settings)) as client:
        login = client.post(f"{API}/auth/login", json={"email": "head@larch.example", "password": PASSWORD})
        assert login.status_code == 200
        me = client.get(f"{API}/me", headers=bearer(login.json()["access_token"])).json()
    assert me["role"] == "admin" and me["full_name"] == "Jo Head" and me["branch_id"] is None


def test_create_admin_exits_1_when_email_has_an_account(tmp_path):
    settings = make_settings(tmp_path)
    assert run(settings, "create-admin", "head@larch.example", "Jo", stdin=PASSWORD)[0] == 0
    code, _, err = run(settings, "create-admin", "HEAD@larch.example", "Jo", stdin=PASSWORD)
    assert code == 1 and "already" in err


@pytest.mark.parametrize(
    "args, password",
    [
        (("head@larch.example", "Jo"), "short"),
        (("not-an-email", "Jo"), PASSWORD),
        (("head@larch.example", ""), PASSWORD),
    ],
)
def test_create_admin_rejects_bad_input(tmp_path, args, password):
    code, out, err = run(make_settings(tmp_path), "create-admin", *args, stdin=password)
    assert code == 2 and out == ""
    assert password not in err


def test_create_admin_prompts_twice_on_a_terminal(tmp_path, monkeypatch):
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    answers = iter([PASSWORD, "different password"])
    monkeypatch.setattr("larch.cli.getpass.getpass", lambda prompt: next(answers))
    err = io.StringIO()
    code = main(["create-admin", "a@larch.example", "Jo"], stdin=Tty(), stdout=io.StringIO(), stderr=err,
                settings=make_settings(tmp_path))
    assert code == 2 and "do not match" in err.getvalue()

    answers = iter([PASSWORD, PASSWORD])
    code = main(["create-admin", "a@larch.example", "Jo"], stdin=Tty(), stdout=io.StringIO(), stderr=io.StringIO(),
                settings=make_settings(tmp_path))
    assert code == 0


def test_purge_refuses_to_run_until_retention_is_decided(tmp_path):
    code, _, err = run(make_settings(tmp_path), "purge-expired")
    assert code == 2 and "not been decided" in err


def test_purge_deletes_closed_applications_past_retention(tmp_path):
    settings = make_settings(tmp_path, retention_days_after_closure=30)
    app = create_app(settings)
    with TestClient(app) as client:
        api = Api(client, app.state.services)
        admin = api.create_admin()
        agent, _ = api.agent(admin, api.branch(admin)["id"])
        listing = api.listing(agent)
        applicants = [api.applicant()[0] for _ in range(4)]
        old_decided = api.submitted_application(applicants[0], listing["id"])
        client.post(f"{API}/applications/{old_decided['id']}/decision", json={"decision": "rejected"},
                    headers=bearer(agent))
        held = api.submitted_application(applicants[1], listing["id"])
        client.post(f"{API}/applications/{held['id']}/withdraw", headers=bearer(applicants[1]))
        recent = api.submitted_application(applicants[2], listing["id"])
        client.post(f"{API}/applications/{recent['id']}/decision", json={"decision": "approved"},
                    headers=bearer(agent))
        open_one = api.submitted_application(applicants[3], listing["id"])

        services = app.state.services
        long_ago = utcnow() - timedelta(days=31)
        A = models.Application
        with services.sessions() as db:
            db.execute(update(A).where(A.id == old_decided["id"]).values(decided_at=long_ago))
            db.execute(update(A).where(A.id == held["id"]).values(withdrawn_at=long_ago, legal_hold=True))
            db.execute(update(A).where(A.id == open_one["id"]).values(submitted_at=long_ago))
            db.commit()
        files_before = sum(1 for p in services.store.root.rglob("*") if p.is_file())

    code, out, _ = run(settings, "purge-expired")
    assert code == 0 and "Deleted 1 application(s) and 2 document(s)" in out
    with services.sessions() as db:
        remaining = set(db.scalars(select(A.id)))
        orphan_docs = db.scalars(select(models.Document).where(models.Document.application_id == old_decided["id"])).all()
    assert remaining == {held["id"], recent["id"], open_one["id"]}
    assert orphan_docs == []
    assert sum(1 for p in services.store.root.rglob("*") if p.is_file()) == files_before - 2
