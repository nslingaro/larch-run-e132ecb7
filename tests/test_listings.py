"""Listings (FR-01, FR-02, FR-16)."""

from __future__ import annotations

import pytest

from tests.conftest import API, bearer, listing_body


def test_agent_creates_a_listing_for_their_branch(client, world):
    response = client.post(f"{API}/listings", json=listing_body(postcode="hg11te"), headers=bearer(world.agent_a))
    assert response.status_code == 201
    listing = response.json()
    assert listing["branch_id"] == world.branch_a["id"]
    assert listing["status"] == "open"
    assert listing["postcode"] == "HG1 1TE"
    assert listing["created_at"].endswith("Z") and listing["updated_at"].endswith("Z")
    assert set(listing) == {"id", "branch_id", "title", "description", "address_line", "city", "postcode",
                            "bedrooms", "monthly_rent", "available_from", "status", "created_at", "updated_at"}


def test_only_agents_create_listings(client, world):
    assert client.post(f"{API}/listings", json=listing_body(), headers=bearer(world.alice)).status_code == 403
    assert client.post(f"{API}/listings", json=listing_body(), headers=bearer(world.admin)).status_code == 403
    assert client.post(f"{API}/listings", json=listing_body()).status_code == 401


@pytest.mark.parametrize(
    "override",
    [
        {"title": ""}, {"title": "x" * 121}, {"description": "x" * 5001}, {"address_line": ""},
        {"city": "x" * 81}, {"postcode": "NOT A POSTCODE"}, {"bedrooms": 11}, {"bedrooms": -1},
        {"bedrooms": "2"}, {"monthly_rent": 0}, {"monthly_rent": 20_001}, {"monthly_rent": 975.5},
        {"available_from": "01/12/2026"}, {"status": "closed"}, {"branch_id": "other"}, {"created_by": "x"},
    ],
)
def test_listing_validation(client, world, override):
    response = client.post(f"{API}/listings", json=listing_body(**override), headers=bearer(world.agent_a))
    assert response.status_code == 422


def test_listing_boundaries_are_accepted(client, world):
    body = listing_body(bedrooms=0, monthly_rent=20_000, description="", title="x" * 120)
    assert client.post(f"{API}/listings", json=body, headers=bearer(world.agent_a)).status_code == 201


def test_listings_show_open_listings_to_everyone(client, world, api):
    closed = api.listing(world.agent_a, title="Already let")
    client.patch(f"{API}/listings/{closed['id']}", json={"status": "closed"}, headers=bearer(world.agent_a))
    for headers in ({}, bearer(world.alice), bearer(world.agent_a), bearer(world.admin)):
        page = client.get(f"{API}/listings", headers=headers).json()
        ids = {item["id"] for item in page["items"]}
        assert ids == {world.listing_a["id"], world.listing_b["id"]}
        assert page["page"] == 1 and page["page_size"] == 20 and page["total"] == 2


def test_listing_filters(client, world, api):
    agent = world.agent_a
    cheap = api.listing(agent, title="Studio", bedrooms=0, monthly_rent=500, available_from="2026-11-20")
    big = api.listing(agent, title="Family home", description="Large GARDEN and garage", bedrooms=4,
                      monthly_rent=1800, available_from="2027-02-01", city="Knaresborough", postcode="HG5 0AA")

    def ids(**params):
        response = client.get(f"{API}/listings", params=params)
        assert response.status_code == 200
        return {item["id"] for item in response.json()["items"]}

    assert ids(city="knaresborough") == {big["id"]}
    assert ids(city="LEEDS") == {world.listing_b["id"]}
    assert ids(min_bedrooms=3) == {big["id"]}
    assert ids(max_rent=600) == {cheap["id"]}
    assert ids(available_by="2026-11-30") == {cheap["id"]}
    assert ids(q="garden") == {big["id"], cheap["id"], world.listing_a["id"], world.listing_b["id"]}
    assert ids(q="family") == {big["id"]}
    assert ids(q="%") == set()  # wildcards are matched literally
    assert ids(q="_") == set()
    assert ids(q="' OR 1=1 --") == set()
    assert ids(city="Harrogate", min_bedrooms=2, max_rent=1000) == {world.listing_a["id"]}


def test_listing_sorting_and_paging(client, world, api):
    agent = world.agent_a
    rents = [700, 1200, 900]
    for rent in rents:
        api.listing(agent, monthly_rent=rent, title=f"Rent {rent}")

    def rent_order(sort):
        items = client.get(f"{API}/listings", params={"sort": sort, "page_size": 100}).json()["items"]
        return [item["monthly_rent"] for item in items]

    assert rent_order("rent") == sorted(rent_order("rent"))
    assert rent_order("-rent") == sorted(rent_order("rent"), reverse=True)
    newest = client.get(f"{API}/listings").json()["items"]
    assert newest[0]["title"] == "Rent 900"  # default: newest first
    dates = [i["available_from"] for i in client.get(f"{API}/listings", params={"sort": "available_from"}).json()["items"]]
    assert dates == sorted(dates)

    page_1 = client.get(f"{API}/listings", params={"page_size": 2, "page": 1}).json()
    page_3 = client.get(f"{API}/listings", params={"page_size": 2, "page": 3}).json()
    assert page_1["total"] == 5 and len(page_1["items"]) == 2 and len(page_3["items"]) == 1


@pytest.mark.parametrize(
    "params",
    [{"sort": "title"}, {"sort": "monthly_rent; DROP TABLE listings"}, {"page": 0}, {"page_size": 101},
     {"page_size": 0}, {"min_bedrooms": 11}, {"max_rent": -1}, {"available_by": "soon"}, {"q": "x" * 101}],
)
def test_listing_query_validation(client, params):
    assert client.get(f"{API}/listings", params=params).status_code == 422


def test_view_open_listing(client, world):
    response = client.get(f"{API}/listings/{world.listing_a['id']}")
    assert response.status_code == 200
    assert response.json() == world.listing_a
    assert client.get(f"{API}/listings/no-such-listing").status_code == 404


def test_closed_listing_visible_only_to_its_branch_agents_and_admins(client, world):
    listing_id = world.listing_a["id"]
    closed = client.patch(f"{API}/listings/{listing_id}", json={"status": "closed"}, headers=bearer(world.agent_a))
    assert closed.status_code == 200 and closed.json()["status"] == "closed"

    assert client.get(f"{API}/listings/{listing_id}", headers=bearer(world.agent_a)).status_code == 200
    assert client.get(f"{API}/listings/{listing_id}", headers=bearer(world.admin)).status_code == 200
    for headers in ({}, bearer(world.alice), bearer(world.agent_b), bearer("stale.or.bad")):
        assert client.get(f"{API}/listings/{listing_id}", headers=headers).status_code == 404


def test_agent_edits_closes_and_reopens_own_listing(client, world):
    listing_id = world.listing_a["id"]
    response = client.patch(
        f"{API}/listings/{listing_id}", json={"monthly_rent": 1000, "title": "Updated"}, headers=bearer(world.agent_a)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["monthly_rent"] == 1000 and body["title"] == "Updated"
    assert body["description"] == world.listing_a["description"]
    for status_value in ("closed", "open"):
        response = client.patch(f"{API}/listings/{listing_id}", json={"status": status_value},
                                headers=bearer(world.agent_a))
        assert response.json()["status"] == status_value


def test_listing_edit_permissions(client, world):
    listing_id = world.listing_a["id"]
    body = {"monthly_rent": 1}
    assert client.patch(f"{API}/listings/{listing_id}", json=body, headers=bearer(world.agent_b)).status_code == 404
    assert client.patch(f"{API}/listings/{listing_id}", json=body, headers=bearer(world.admin)).status_code == 403
    assert client.patch(f"{API}/listings/{listing_id}", json=body, headers=bearer(world.alice)).status_code == 403
    assert client.patch(f"{API}/listings/{listing_id}", json=body).status_code == 401
    assert client.patch(f"{API}/listings/missing", json=body, headers=bearer(world.agent_a)).status_code == 404


@pytest.mark.parametrize(
    "body",
    [{"status": "let"}, {"branch_id": "x"}, {"title": None}, {"bedrooms": 99}, {"created_at": "2020-01-01T00:00:00Z"}],
)
def test_listing_patch_validation(client, world, body):
    response = client.patch(f"{API}/listings/{world.listing_a['id']}", json=body, headers=bearer(world.agent_a))
    assert response.status_code == 422
