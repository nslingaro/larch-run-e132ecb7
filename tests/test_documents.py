"""Documents: upload, list, download, delete (FR-08, FR-09, FR-14) and their storage."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote

import pytest
from sqlalchemy import select

from larch import models
from larch.security.document_crypto import DocumentCipher, generate_key_b64, parse_keyring
from larch.storage import DocumentStore, StorageError
from larch.uploads import MAX_DOCUMENT_BYTES, content_disposition
from tests.conftest import API, JPEG, PDF, PNG, bearer


@pytest.fixture
def draft(world, api):
    return api.application(world.alice, world.listing_a["id"])


def _stored_files(services) -> list[Path]:
    return [p for p in services.store.root.rglob("*") if p.is_file()]


# --- upload ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content, filename, content_type",
    [(PDF, "passport.pdf", "application/pdf"), (JPEG, "licence.JPG", "image/jpeg"),
     (JPEG, "licence.jpeg", "image/jpeg"), (PNG, "payslip.png", "image/png")],
)
def test_upload_accepted_types(api, world, draft, content, filename, content_type):
    response = api.upload(world.alice, draft["id"], "proof_of_income", content, filename, content_type)
    assert response.status_code == 201
    body = response.json()
    assert body["application_id"] == draft["id"] and body["kind"] == "proof_of_income"
    assert body["filename"] == filename and body["content_type"] == content_type
    assert body["size_bytes"] == len(content) and body["uploaded_at"].endswith("Z")
    assert set(body) == {"id", "application_id", "kind", "filename", "content_type", "size_bytes", "uploaded_at"}


def test_documents_are_encrypted_at_rest_under_random_names(api, world, draft, services):
    marker = b"PASSPORT-NUMBER-123456789"
    response = api.upload(world.alice, draft["id"], content=PDF + marker, filename="../../etc/passport.pdf")
    assert response.status_code == 201
    assert response.json()["filename"] == "passport.pdf"
    files = _stored_files(services)
    assert len(files) == 1
    stored = files[0].read_bytes()
    assert marker not in stored and not stored.startswith(b"%PDF")
    assert "passport" not in str(files[0])
    assert files[0].resolve().is_relative_to(services.store.root)
    if os.name == "posix":
        assert files[0].stat().st_mode & 0o077 == 0
    with services.sessions() as db:
        document = db.scalar(select(models.Document))
    assert document.encryption_key_id == "k1" and len(document.wrapped_data_key) > 32


@pytest.mark.parametrize(
    "content, filename, content_type",
    [
        (b"MZ\x90\x00 executable", "passport.pdf", "application/pdf"),  # wrong signature
        (b"<html><script>alert(1)</script>", "passport.pdf", "application/pdf"),
        (PNG, "passport.pdf", "application/pdf"),  # declared type does not match the content
        (PDF, "passport.png", "application/pdf"),  # extension does not match
        (PDF, "passport.exe", "application/pdf"),
        (PDF, "passport", "application/pdf"),
        (PDF, "passport.pdf", "application/octet-stream"),
        (b"PK\x03\x04 zip archive", "docs.zip", "application/zip"),
        (b"", "empty.pdf", "application/pdf"),
    ],
)
def test_upload_rejects_other_types(api, world, draft, services, content, filename, content_type):
    response = api.upload(world.alice, draft["id"], "photo_id", content, filename, content_type)
    assert response.status_code == 415
    assert response.json() == {"detail": "Only PDF, JPEG or PNG files are accepted"}
    assert _stored_files(services) == []


def test_upload_size_limit(api, world, draft, services):
    exactly = PDF + b"0" * (MAX_DOCUMENT_BYTES - len(PDF))
    assert api.upload(world.alice, draft["id"], content=exactly).status_code == 201
    too_big = exactly + b"0"
    assert api.upload(world.alice, draft["id"], content=too_big).status_code == 413
    way_too_big = exactly * 2
    assert api.upload(world.alice, draft["id"], content=way_too_big).status_code == 413
    assert len(_stored_files(services)) == 1


def test_upload_requires_a_valid_kind_and_file(api, client, world, draft):
    assert api.upload(world.alice, draft["id"], kind="passport").status_code == 422
    url = f"{API}/applications/{draft['id']}/documents"
    assert client.post(url, data={"kind": "photo_id"}, files={"other": ("a.pdf", PDF, "application/pdf")},
                       headers=bearer(world.alice)).status_code == 422
    assert client.post(url, json={"kind": "photo_id"}, headers=bearer(world.alice)).status_code == 415


def test_upload_long_filename_is_rejected(api, world, draft):
    response = api.upload(world.alice, draft["id"], filename="a" * 252 + ".pdf")
    assert response.status_code == 422
    assert api.upload(world.alice, draft["id"], filename="a" * 251 + ".pdf").status_code == 201


def test_upload_limit_of_ten_documents(api, world, draft):
    for _ in range(10):
        assert api.upload(world.alice, draft["id"], "other").status_code == 201
    response = api.upload(world.alice, draft["id"], "other")
    assert response.status_code == 409
    assert response.json() == {"detail": "An application can hold at most 10 documents"}


def test_upload_only_to_own_drafts(api, client, world, draft):
    assert api.upload(world.bob, draft["id"]).status_code == 404
    assert api.upload(world.agent_a, draft["id"]).status_code == 403
    assert api.upload(world.admin, draft["id"]).status_code == 403
    submitted = api.submitted_application(world.bob, world.listing_a["id"])
    assert api.upload(world.bob, submitted["id"]).status_code == 409
    assert client.post(f"{API}/applications/{draft['id']}/documents", data={"kind": "other"},
                       files={"file": ("a.pdf", PDF, "application/pdf")}).status_code == 401


def test_upload_rate_limit(tmp_path):
    from fastapi.testclient import TestClient

    from larch.app import create_app
    from tests.conftest import Api, World, make_settings  # noqa: F401

    app = create_app(make_settings(tmp_path, rate_limit_upload_per_user="2/60"))
    with TestClient(app) as client:
        api = Api(client, app.state.services)
        admin = api.create_admin()
        agent, _ = api.agent(admin, api.branch(admin)["id"])
        applicant, _ = api.applicant()
        draft = api.application(applicant, api.listing(agent)["id"])
        statuses = [api.upload(applicant, draft["id"]).status_code for _ in range(3)]
    assert statuses == [201, 201, 429]


# --- list and download ----------------------------------------------------------------


def test_owner_lists_and_downloads(api, client, world, draft):
    uploaded = api.upload(world.alice, draft["id"], "photo_id", PDF, "Pässport scan.pdf").json()
    listed = client.get(f"{API}/applications/{draft['id']}/documents", headers=bearer(world.alice))
    assert listed.status_code == 200 and listed.json() == [uploaded]

    response = client.get(f"{API}/applications/{draft['id']}/documents/{uploaded['id']}/content",
                          headers=bearer(world.alice))
    assert response.status_code == 200
    assert response.content == PDF
    assert response.headers["content-type"] == "application/pdf"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert unquote(disposition.split("filename*=UTF-8''")[1]) == "Pässport scan.pdf"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_branch_agents_and_admins_download_submitted_documents(api, client, world):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    documents = client.get(f"{API}/applications/{application['id']}/documents", headers=bearer(world.agent_a)).json()
    assert {d["kind"] for d in documents} == {"photo_id", "proof_of_income"}
    url = f"{API}/applications/{application['id']}/documents/{documents[0]['id']}/content"
    assert client.get(url, headers=bearer(world.agent_a)).content == PDF
    assert client.get(url, headers=bearer(world.admin)).content == PDF
    assert client.get(url, headers=bearer(world.agent_b)).status_code == 404
    assert client.get(url, headers=bearer(world.bob)).status_code == 404
    assert client.get(url).status_code == 401


def test_staff_cannot_reach_draft_documents(api, client, world, draft):
    document = api.upload(world.alice, draft["id"]).json()
    url = f"{API}/applications/{draft['id']}/documents/{document['id']}/content"
    for token in (world.agent_a, world.admin):
        assert client.get(url, headers=bearer(token)).status_code == 404


def test_document_must_belong_to_the_application_in_the_path(api, client, world, draft):
    """A document id from another application cannot be fetched through one the caller can see."""
    bobs = api.application(world.bob, world.listing_a["id"])
    bobs_document = api.upload(world.bob, bobs["id"]).json()
    url = f"{API}/applications/{draft['id']}/documents/{bobs_document['id']}/content"
    assert client.get(url, headers=bearer(world.alice)).status_code == 404
    delete_url = f"{API}/applications/{draft['id']}/documents/{bobs_document['id']}"
    assert client.delete(delete_url, headers=bearer(world.alice)).status_code == 404
    assert client.get(f"{API}/applications/{draft['id']}/documents/no-such-doc/content",
                      headers=bearer(world.alice)).status_code == 404


def test_tampered_file_fails_closed(api, client, world, draft, services):
    document = api.upload(world.alice, draft["id"]).json()
    path = _stored_files(services)[0]
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))
    response = client.get(f"{API}/applications/{draft['id']}/documents/{document['id']}/content",
                          headers=bearer(world.alice))
    assert response.status_code == 500
    assert set(response.json()) == {"detail", "request_id"}
    assert "%PDF" not in response.text


def test_missing_file_is_a_generic_error(api, client, world, draft, services):
    document = api.upload(world.alice, draft["id"]).json()
    _stored_files(services)[0].unlink()
    response = client.get(f"{API}/applications/{draft['id']}/documents/{document['id']}/content",
                          headers=bearer(world.alice))
    assert response.status_code == 500
    assert str(services.store.root) not in response.text


# --- delete ---------------------------------------------------------------------------


def test_owner_deletes_from_a_draft(api, client, world, draft, services):
    document = api.upload(world.alice, draft["id"]).json()
    url = f"{API}/applications/{draft['id']}/documents/{document['id']}"
    assert client.delete(url, headers=bearer(world.bob)).status_code == 404
    assert client.delete(url, headers=bearer(world.agent_a)).status_code == 403
    assert client.delete(url, headers=bearer(world.alice)).status_code == 204
    assert _stored_files(services) == []
    assert client.get(f"{API}/applications/{draft['id']}/documents", headers=bearer(world.alice)).json() == []
    assert client.delete(url, headers=bearer(world.alice)).status_code == 404


def test_cannot_delete_from_a_submitted_application(api, client, world):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    document = client.get(f"{API}/applications/{application['id']}/documents", headers=bearer(world.alice)).json()[0]
    response = client.delete(f"{API}/applications/{application['id']}/documents/{document['id']}",
                             headers=bearer(world.alice))
    assert response.status_code == 409


# --- storage and crypto units -------------------------------------------------------------


def test_store_rejects_keys_that_are_not_its_own(tmp_path):
    store = DocumentStore(tmp_path / "docs")
    store.ensure_root()
    for key in ("../secret", "/etc/passwd", "ab/../../x", "..%2f..%2fetc", "AB/" + "0" * 32, "ab/" + "0" * 31, ""):
        with pytest.raises(StorageError):
            store.get(key)
        with pytest.raises(StorageError):
            store.put(key, b"x")


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_store_refuses_to_follow_symlinks_out_of_the_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ("a" * 32)).write_bytes(b"secret")
    store = DocumentStore(tmp_path / "docs")
    store.ensure_root()
    (store.root / "aa").symlink_to(outside, target_is_directory=True)
    with pytest.raises(StorageError):
        store.get("aa/" + "a" * 32)
    with pytest.raises(StorageError):
        store.put("aa/" + "b" * 32, b"x")
    (store.root / "bb").mkdir()
    (store.root / "bb" / ("c" * 32)).symlink_to(outside / ("a" * 32))
    with pytest.raises(StorageError):
        store.get("bb/" + "c" * 32)


def test_storage_keys_are_random_and_never_reused(tmp_path):
    keys = {DocumentStore.new_key() for _ in range(1000)}
    assert len(keys) == 1000
    store = DocumentStore(tmp_path)
    key = DocumentStore.new_key()
    store.put(key, b"one")
    with pytest.raises(StorageError):
        store.put(key, b"two")


def test_cipher_binds_files_to_their_record_and_supports_rotation():
    old_key, new_key = generate_key_b64(), generate_key_b64()
    old = DocumentCipher(parse_keyring(f"old:{old_key}"), "old")
    blob = old.encrypt(b"payslip", b"aa/" + b"1" * 32)
    rotated = DocumentCipher(parse_keyring(f"old:{old_key},new:{new_key}"), "new")
    assert rotated.decrypt(blob.key_id, blob.wrapped_data_key, blob.ciphertext, b"aa/" + b"1" * 32) == b"payslip"
    assert rotated.encrypt(b"x", b"k").key_id == "new"
    from larch.security.document_crypto import DecryptionError

    with pytest.raises(DecryptionError):
        rotated.decrypt(blob.key_id, blob.wrapped_data_key, blob.ciphertext, b"aa/" + b"2" * 32)
    with pytest.raises(DecryptionError):
        DocumentCipher(parse_keyring(f"new:{new_key}"), "new").decrypt(
            blob.key_id, blob.wrapped_data_key, blob.ciphertext, b"aa/" + b"1" * 32
        )


@pytest.mark.parametrize("spec", ["", "nokey", "k1:not-base64!", "k1:" + "QUJD", "bad id:" + "A" * 44])
def test_keyring_rejects_bad_configuration(spec):
    with pytest.raises(ValueError):
        parse_keyring(spec)


def test_content_disposition_cannot_inject_headers():
    header = content_disposition('evil"\r\nSet-Cookie: x=1.pdf')
    assert "\r" not in header and "\n" not in header
    assert header.count('"') == 2
