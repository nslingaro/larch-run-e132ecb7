"""Branches and agent accounts (FR-17, FR-18, FR-19)."""

from __future__ import annotations

from tests.conftest import API, PASSWORD, bearer, unique_email


def test_branches_are_public(client, world):
    response = client.get(f"{API}/branches")
    assert response.status_code == 200
    assert response.json() == [
        {"id": world.branch_a["id"], "name": "Harrogate", "city": "Harrogate"},
        {"id": world.branch_b["id"], "name": "Leeds", "city": "Leeds"},
    ]


def test_admin_creates_a_branch(client, world):
    response = client.post(f"{API}/admin/branches", json={"name": "York", "city": "York"}, headers=bearer(world.admin))
    assert response.status_code == 201
    assert set(response.json()) == {"id", "name", "city"}
    assert response.json()["name"] == "York"


def test_branch_name_in_use_is_a_conflict(client, world):
    response = client.post(f"{API}/admin/branches", json={"name": "harrogate", "city": "X"}, headers=bearer(world.admin))
    assert response.status_code == 409


def test_branch_validation(client, world):
    for body in ({"name": "", "city": "X"}, {"name": "x" * 81, "city": "X"}, {"name": "Y"},
                 {"name": "Y", "city": "Y", "id": "chosen"}):
        assert client.post(f"{API}/admin/branches", json=body, headers=bearer(world.admin)).status_code == 422


def test_only_admins_manage_branches_and_agents(client, world):
    for token in (world.agent_a, world.alice):
        headers = bearer(token)
        assert client.post(f"{API}/admin/branches", json={"name": "Z", "city": "Z"}, headers=headers).status_code == 403
        assert client.get(f"{API}/admin/agents", headers=headers).status_code == 403
        assert client.post(f"{API}/admin/agents", json={}, headers=headers).status_code == 403
        assert client.patch(f"{API}/admin/agents/{world.agent_a_user['id']}", json={"active": False},
                            headers=headers).status_code == 403
    assert client.get(f"{API}/admin/agents").status_code == 401
    assert client.post(f"{API}/admin/branches", json={"name": "Z", "city": "Z"}).status_code == 401


def test_admin_creates_and_lists_agents(client, world):
    email = unique_email("agent")
    response = client.post(
        f"{API}/admin/agents",
        json={"email": email, "full_name": "Pat Agent", "branch_id": world.branch_b["id"], "initial_password": PASSWORD},
        headers=bearer(world.admin),
    )
    assert response.status_code == 201
    agent = response.json()
    assert agent["role"] == "agent" and agent["branch_id"] == world.branch_b["id"] and agent["active"] is True
    listed = client.get(f"{API}/admin/agents", headers=bearer(world.admin)).json()
    assert agent in listed
    assert {u["role"] for u in listed} == {"agent"}
    assert client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200


def test_agent_email_in_use_is_a_conflict(client, world):
    for email in (world.agent_a_user["email"].upper(), unique_email()):
        if "AGENT" not in email:
            client.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD, "full_name": "S"})
        response = client.post(
            f"{API}/admin/agents",
            json={"email": email, "full_name": "Dup", "branch_id": world.branch_a["id"], "initial_password": PASSWORD},
            headers=bearer(world.admin),
        )
        assert response.status_code == 409


def test_agent_for_missing_branch_is_422(client, world):
    response = client.post(
        f"{API}/admin/agents",
        json={"email": unique_email(), "full_name": "X", "branch_id": "no-such-branch", "initial_password": PASSWORD},
        headers=bearer(world.admin),
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "branch_id"]


def test_agent_validation(client, world):
    base = {"email": unique_email(), "full_name": "X", "branch_id": world.branch_a["id"], "initial_password": PASSWORD}
    for override in ({"initial_password": "short"}, {"email": "nope"}, {"role": "admin"}, {"active": False}):
        response = client.post(f"{API}/admin/agents", json={**base, **override}, headers=bearer(world.admin))
        assert response.status_code == 422


def test_deactivation_takes_effect_immediately_and_can_be_reversed(client, world):
    agent_id = world.agent_a_user["id"]
    assert client.get(f"{API}/me", headers=bearer(world.agent_a)).status_code == 200

    response = client.patch(f"{API}/admin/agents/{agent_id}", json={"active": False}, headers=bearer(world.admin))
    assert response.status_code == 200 and response.json()["active"] is False
    assert client.get(f"{API}/me", headers=bearer(world.agent_a)).status_code == 401
    assert client.get(f"{API}/applications", headers=bearer(world.agent_a)).status_code == 401
    login = {"email": world.agent_a_user["email"], "password": PASSWORD}
    assert client.post(f"{API}/auth/login", json=login).status_code == 401

    response = client.patch(f"{API}/admin/agents/{agent_id}", json={"active": True}, headers=bearer(world.admin))
    assert response.status_code == 200 and response.json()["active"] is True
    # Old sessions stay ended; the agent signs in again.
    assert client.get(f"{API}/me", headers=bearer(world.agent_a)).status_code == 401
    assert client.post(f"{API}/auth/login", json=login).status_code == 200


def test_patch_agent_rejects_bad_bodies_and_non_agents(client, world):
    agent_id = world.agent_a_user["id"]
    for body in ({}, {"active": "false"}, {"active": None}, {"active": False, "role": "admin"}):
        assert client.patch(f"{API}/admin/agents/{agent_id}", json=body, headers=bearer(world.admin)).status_code == 422
    for target in (world.alice_id, "no-such-id"):
        response = client.patch(f"{API}/admin/agents/{target}", json={"active": False}, headers=bearer(world.admin))
        assert response.status_code == 404
