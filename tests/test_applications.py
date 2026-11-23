"""Applications (FR-06 to FR-15, FR-19) and access control between roles and branches."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from larch.schemas import today_utc
from tests.conftest import API, application_body, bearer


def _years_ago(years: int, extra_days: int = 0) -> date:
    today = today_utc()
    try:
        anniversary = today.replace(year=today.year - years)
    except ValueError:  # 29 February
        anniversary = today.replace(year=today.year - years, day=28)
    return anniversary + timedelta(days=extra_days)


# --- starting ------------------------------------------------------------------------


def test_applicant_starts_a_draft(client, world):
    response = client.post(
        f"{API}/listings/{world.listing_a['id']}/applications", json=application_body(), headers=bearer(world.alice)
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "draft"
    assert body["listing_id"] == world.listing_a["id"]
    assert body["applicant_id"] == world.alice_id
    assert body["submitted_at"] is None and body["decided_at"] is None and body["withdrawn_at"] is None
    assert body["created_at"].endswith("Z")
    assert "decision_note" not in body
    assert body["full_name"] == "Sam Carter" and body["annual_income"] == 34000


def test_only_applicants_start_applications(client, world):
    url = f"{API}/listings/{world.listing_a['id']}/applications"
    assert client.post(url, json=application_body(), headers=bearer(world.agent_a)).status_code == 403
    assert client.post(url, json=application_body(), headers=bearer(world.admin)).status_code == 403
    assert client.post(url, json=application_body()).status_code == 401


def test_cannot_apply_twice_even_after_withdrawing(client, world, api):
    first = api.application(world.alice, world.listing_a["id"])
    url = f"{API}/listings/{world.listing_a['id']}/applications"
    again = client.post(url, json=application_body(), headers=bearer(world.alice))
    assert again.status_code == 409
    assert again.json() == {"detail": "You have already applied for this listing"}
    client.post(f"{API}/applications/{first['id']}/withdraw", headers=bearer(world.alice))
    assert client.post(url, json=application_body(), headers=bearer(world.alice)).status_code == 409
    # A different applicant may still apply.
    assert client.post(url, json=application_body(), headers=bearer(world.bob)).status_code == 201


def test_cannot_apply_to_closed_or_missing_listing(client, world):
    client.patch(f"{API}/listings/{world.listing_a['id']}", json={"status": "closed"}, headers=bearer(world.agent_a))
    for listing_id in (world.listing_a["id"], "no-such-listing"):
        response = client.post(f"{API}/listings/{listing_id}/applications", json=application_body(),
                               headers=bearer(world.alice))
        assert response.status_code == 404


def test_applicant_must_be_eighteen_on_the_day(client, world, api):
    url = f"{API}/listings/{world.listing_a['id']}/applications"
    too_young = _years_ago(18, extra_days=1).isoformat()
    response = client.post(url, json=application_body(date_of_birth=too_young), headers=bearer(world.alice))
    assert response.status_code == 422
    assert "18 or over" in response.json()["detail"][0]["msg"]
    eighteen_today = _years_ago(18).isoformat()
    assert client.post(url, json=application_body(date_of_birth=eighteen_today), headers=bearer(world.alice)).status_code == 201


@pytest.mark.parametrize(
    "override",
    [
        {"full_name": ""}, {"full_name": "x" * 101}, {"date_of_birth": "1800-01-01"}, {"date_of_birth": "2999-01-01"},
        {"phone": "call me"}, {"phone": "0" * 21}, {"contact_email": "nope"}, {"current_address": "x" * 301},
        {"employment_status": "pirate"}, {"employer_name": "x" * 101}, {"annual_income": -1},
        {"annual_income": 10_000_001}, {"annual_income": "34000"}, {"occupants": 0}, {"occupants": 11},
        {"pets": "no"}, {"notes": "x" * 2001}, {"move_in_date": "soon"},
        # Mass assignment: none of these can be set by the client.
        {"status": "approved"}, {"applicant_id": "someone-else"}, {"listing_id": "other"},
        {"decision_note": "approve me"}, {"submitted_at": "2026-01-01T00:00:00Z"}, {"id": "chosen"},
    ],
)
def test_application_validation(client, world, override):
    response = client.post(
        f"{API}/listings/{world.listing_a['id']}/applications", json=application_body(**override),
        headers=bearer(world.alice),
    )
    assert response.status_code == 422


def test_optional_fields_may_be_omitted(client, world):
    body = application_body()
    del body["employer_name"], body["notes"]
    response = client.post(f"{API}/listings/{world.listing_a['id']}/applications", json=body,
                           headers=bearer(world.alice))
    assert response.status_code == 201
    assert response.json()["employer_name"] is None and response.json()["notes"] is None


# --- editing -------------------------------------------------------------------------


def test_owner_edits_a_draft(client, world, api):
    application = api.application(world.alice, world.listing_a["id"])
    response = client.patch(
        f"{API}/applications/{application['id']}",
        json={"annual_income": 41000, "employer_name": None, "notes": "Two cats, both very calm."},
        headers=bearer(world.alice),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["annual_income"] == 41000 and body["employer_name"] is None
    assert body["notes"] == "Two cats, both very calm."
    assert body["full_name"] == application["full_name"]


@pytest.mark.parametrize(
    "body",
    [{"full_name": None}, {"status": "submitted"}, {"applicant_id": "x"}, {"decision_note": "x"},
     {"occupants": 50}, {"date_of_birth": "2020-01-01"}],
)
def test_draft_edit_validation(client, world, api, body):
    application = api.application(world.alice, world.listing_a["id"])
    response = client.patch(f"{API}/applications/{application['id']}", json=body, headers=bearer(world.alice))
    assert response.status_code == 422


def test_only_drafts_can_be_edited(client, world, api):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    response = client.patch(f"{API}/applications/{application['id']}", json={"occupants": 3},
                            headers=bearer(world.alice))
    assert response.status_code == 409
    assert response.json() == {"detail": "Only draft applications can be changed"}


def test_only_the_owner_edits(client, world, api):
    application = api.application(world.alice, world.listing_a["id"])
    url = f"{API}/applications/{application['id']}"
    assert client.patch(url, json={"occupants": 3}, headers=bearer(world.bob)).status_code == 404
    assert client.patch(url, json={"occupants": 3}, headers=bearer(world.agent_a)).status_code == 403
    assert client.patch(url, json={"occupants": 3}, headers=bearer(world.admin)).status_code == 403


# --- submitting and withdrawing ----------------------------------------------------------


def test_submit_requires_photo_id_and_proof_of_income(client, world, api):
    application = api.application(world.alice, world.listing_a["id"])
    url = f"{API}/applications/{application['id']}/submit"
    for kind in (None, "photo_id", "proof_of_address"):
        if kind:
            assert api.upload(world.alice, application["id"], kind).status_code == 201
        response = client.post(url, headers=bearer(world.alice))
        assert response.status_code == 422
        assert response.json() == {"detail": "Photo ID and proof of income are required"}
    api.upload(world.alice, application["id"], "proof_of_income")
    response = client.post(url, headers=bearer(world.alice))
    assert response.status_code == 200
    assert response.json()["status"] == "submitted" and response.json()["submitted_at"].endswith("Z")


def test_submit_rules(client, world, api):
    application = api.application(world.alice, world.listing_a["id"])
    api.upload(world.alice, application["id"], "photo_id")
    api.upload(world.alice, application["id"], "proof_of_income")
    url = f"{API}/applications/{application['id']}/submit"

    client.patch(f"{API}/listings/{world.listing_a['id']}", json={"status": "closed"}, headers=bearer(world.agent_a))
    response = client.post(url, headers=bearer(world.alice))
    assert response.status_code == 409 and response.json() == {"detail": "Listing is closed"}

    client.patch(f"{API}/listings/{world.listing_a['id']}", json={"status": "open"}, headers=bearer(world.agent_a))
    assert client.post(url, headers=bearer(world.bob)).status_code == 404
    assert client.post(url, headers=bearer(world.agent_a)).status_code == 403
    assert client.post(url, headers=bearer(world.alice)).status_code == 200
    assert client.post(url, headers=bearer(world.alice)).status_code == 409


def test_closing_a_listing_leaves_its_applications_alone(client, world, api):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    client.patch(f"{API}/listings/{world.listing_a['id']}", json={"status": "closed"}, headers=bearer(world.agent_a))
    response = client.get(f"{API}/applications/{application['id']}", headers=bearer(world.alice))
    assert response.json()["status"] == "submitted"


def test_withdraw_from_draft_or_submitted_only(client, world, api):
    draft = api.application(world.alice, world.listing_a["id"])
    response = client.post(f"{API}/applications/{draft['id']}/withdraw", headers=bearer(world.alice))
    assert response.status_code == 200
    assert response.json()["status"] == "withdrawn" and response.json()["withdrawn_at"].endswith("Z")
    assert client.post(f"{API}/applications/{draft['id']}/withdraw", headers=bearer(world.alice)).status_code == 409

    submitted = api.submitted_application(world.alice, world.listing_b["id"])
    url = f"{API}/applications/{submitted['id']}/withdraw"
    assert client.post(url, headers=bearer(world.bob)).status_code == 404
    assert client.post(url, headers=bearer(world.agent_b)).status_code == 403
    assert client.post(url, headers=bearer(world.alice)).json()["status"] == "withdrawn"


def test_cannot_withdraw_after_a_decision(client, world, api):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    client.post(f"{API}/applications/{application['id']}/decision", json={"decision": "approved"},
                headers=bearer(world.agent_a))
    response = client.post(f"{API}/applications/{application['id']}/withdraw", headers=bearer(world.alice))
    assert response.status_code == 409


# --- decisions -------------------------------------------------------------------------


def test_branch_agent_records_a_decision_with_a_private_note(client, world, api):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    url = f"{API}/applications/{application['id']}"
    response = client.post(f"{url}/decision", json={"decision": "rejected", "note": "Income below 30x rent"},
                           headers=bearer(world.agent_a))
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "rejected" and body["decision_note"] == "Income below 30x rent"
    assert body["decided_at"].endswith("Z")

    applicant_view = client.get(url, headers=bearer(world.alice)).json()
    assert applicant_view["status"] == "rejected"
    assert "decision_note" not in applicant_view
    listed = client.get(f"{API}/applications", headers=bearer(world.alice)).json()["items"]
    assert all("decision_note" not in item for item in listed)
    assert "Income below" not in client.get(f"{API}/applications", headers=bearer(world.alice)).text

    assert client.get(url, headers=bearer(world.admin)).json()["decision_note"] == "Income below 30x rent"
    assert client.get(url, headers=bearer(world.agent_a)).json()["decision_note"] == "Income below 30x rent"


def test_decision_rules(client, world, api):
    application = api.submitted_application(world.alice, world.listing_a["id"])
    url = f"{API}/applications/{application['id']}/decision"
    assert client.post(url, json={"decision": "approved"}, headers=bearer(world.agent_b)).status_code == 404
    assert client.post(url, json={"decision": "approved"}, headers=bearer(world.admin)).status_code == 403
    assert client.post(url, json={"decision": "approved"}, headers=bearer(world.alice)).status_code == 403
    for body in ({"decision": "maybe"}, {"decision": "approved", "note": "x" * 2001}, {},
                 {"decision": "approved", "decided_by": "someone"}):
        assert client.post(url, json=body, headers=bearer(world.agent_a)).status_code == 422
    response = client.post(url, json={"decision": "approved"}, headers=bearer(world.agent_a))
    assert response.status_code == 200 and response.json()["decision_note"] is None
    assert client.post(url, json={"decision": "rejected"}, headers=bearer(world.agent_a)).status_code == 409


def test_drafts_cannot_be_decided(client, world, api):
    draft = api.application(world.alice, world.listing_a["id"])
    response = client.post(f"{API}/applications/{draft['id']}/decision", json={"decision": "approved"},
                           headers=bearer(world.agent_a))
    assert response.status_code == 404  # agents never see drafts


# --- lists and visibility ------------------------------------------------------------------


def test_applicant_sees_only_their_own_applications(client, world, api):
    mine = api.application(world.alice, world.listing_a["id"])
    other = api.application(world.bob, world.listing_a["id"])
    page = client.get(f"{API}/applications", headers=bearer(world.alice)).json()
    assert [item["id"] for item in page["items"]] == [mine["id"]]
    assert page["total"] == 1 and page["page"] == 1 and page["page_size"] == 20
    assert client.get(f"{API}/applications/{other['id']}", headers=bearer(world.alice)).status_code == 404
    assert client.get(f"{API}/applications/{mine['id']}", headers=bearer(world.alice)).status_code == 200


def test_staff_never_see_drafts_or_applications_withdrawn_before_submission(client, world, api):
    draft = api.application(world.alice, world.listing_a["id"])
    early_withdrawal = api.application(world.bob, world.listing_a["id"])
    client.post(f"{API}/applications/{early_withdrawal['id']}/withdraw", headers=bearer(world.bob))
    carol, _ = api.applicant()
    late_withdrawal = api.submitted_application(carol, world.listing_a["id"])
    client.post(f"{API}/applications/{late_withdrawal['id']}/withdraw", headers=bearer(carol))
    dave, _ = api.applicant()
    submitted = api.submitted_application(dave, world.listing_a["id"])

    for token in (world.agent_a, world.admin):
        ids = {item["id"] for item in client.get(f"{API}/applications", headers=bearer(token)).json()["items"]}
        assert ids == {late_withdrawal["id"], submitted["id"]}
        for hidden in (draft, early_withdrawal):
            assert client.get(f"{API}/applications/{hidden['id']}", headers=bearer(token)).status_code == 404
            assert client.get(f"{API}/applications/{hidden['id']}/documents", headers=bearer(token)).status_code == 404
        drafts = client.get(f"{API}/applications", params={"status": "draft"}, headers=bearer(token)).json()
        assert drafts["items"] == [] and drafts["total"] == 0


def test_agents_see_only_their_branch_and_admins_see_all(client, world, api):
    in_a = api.submitted_application(world.alice, world.listing_a["id"])
    in_b = api.submitted_application(world.bob, world.listing_b["id"])

    def ids(token, **params):
        return [item["id"] for item in client.get(f"{API}/applications", params=params, headers=bearer(token)).json()["items"]]

    assert ids(world.agent_a) == [in_a["id"]]
    assert ids(world.agent_b) == [in_b["id"]]
    assert ids(world.admin) == [in_b["id"], in_a["id"]]  # most recently created first
    assert ids(world.admin, listing_id=world.listing_a["id"]) == [in_a["id"]]
    assert ids(world.agent_a, listing_id=world.listing_b["id"]) == []
    assert ids(world.admin, status="approved") == []

    # BOLA: swapping in another branch's identifier never grants access.
    assert client.get(f"{API}/applications/{in_b['id']}", headers=bearer(world.agent_a)).status_code == 404
    assert client.get(f"{API}/applications/{in_b['id']}/documents", headers=bearer(world.agent_a)).status_code == 404


def test_agent_filters_by_listing_and_status(client, world, api):
    other_listing = api.listing(world.agent_a, title="Other")
    first = api.submitted_application(world.alice, world.listing_a["id"])
    second = api.submitted_application(world.bob, other_listing["id"])
    client.post(f"{API}/applications/{second['id']}/decision", json={"decision": "approved"},
                headers=bearer(world.agent_a))

    def ids(**params):
        return [i["id"] for i in client.get(f"{API}/applications", params=params, headers=bearer(world.agent_a)).json()["items"]]

    assert ids(listing_id=world.listing_a["id"]) == [first["id"]]
    assert ids(status="approved") == [second["id"]]
    assert ids(status="submitted", listing_id=other_listing["id"]) == []


def test_application_list_paging_and_validation(client, world, api):
    for listing in (world.listing_a, world.listing_b, api.listing(world.agent_a)):
        api.application(world.alice, listing["id"])
    page = client.get(f"{API}/applications", params={"page_size": 2, "page": 2}, headers=bearer(world.alice)).json()
    assert page["total"] == 3 and len(page["items"]) == 1 and page["page"] == 2
    for params in ({"status": "lost"}, {"page": 0}, {"page_size": 101}):
        assert client.get(f"{API}/applications", params=params, headers=bearer(world.alice)).status_code == 422
    assert client.get(f"{API}/applications").status_code == 401


def test_missing_application_is_404_for_everyone(client, world):
    for token in (world.alice, world.agent_a, world.admin):
        assert client.get(f"{API}/applications/does-not-exist", headers=bearer(token)).status_code == 404
