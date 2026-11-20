from datetime import datetime, timedelta, timezone

from z3r0_platform.database import make_engine


def auth_headers():
    return {"X-API-Token": "test-token"}


def create_project(client):
    response = client.post("/projects", json={
        "name": "supervisor-test",
        "budget_limit_units": 20,
        "iteration_limit": 10,
        "scopes": [{
            "host": "example.com",
            "scheme": "https",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        }],
    }, headers=auth_headers())
    assert response.status_code == 201, response.text
    return response.json()


def authorize_task(client, project_id):
    task = client.post(f"/projects/{project_id}/tasks", json={
        "action": "offline_analysis",
        "target_url": "https://example.com/source",
        "objective": "Analyze imported metadata only.",
        "requested_budget_units": 5,
        "requested_iterations": 3,
    }, headers=auth_headers())
    assert task.status_code == 201, task.text
    return task.json()


def import_observation(client, project_id):
    response = client.post(f"/projects/{project_id}/evidence", json={
        "schema_version": "1",
        "source_tool": "fixture",
        "run_status": "partial",
        "observations": [{
            "kind": "finding_candidate",
            "subject": "https://example.com/api/items",
            "data": {"template": "fixture-check", "confidence": "candidate"},
        }],
    }, headers=auth_headers())
    assert response.status_code == 201, response.text
    body = response.json()
    return body["observations"][0]["id"]


def test_supervisor_lifecycle_is_persistent_and_bounded(client):
    project = create_project(client)
    task = authorize_task(client, project["id"])
    authorized = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert authorized.status_code == 200, authorized.text

    created = client.post(f"/tasks/{task['id']}/investigations", headers=auth_headers())
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    observation_id = import_observation(client, project["id"])
    hypothesis = client.post(f"/investigations/{investigation_id}/hypotheses", json={
        "category": "api.authorization",
        "statement": "The endpoint may enforce object-level authorization inconsistently.",
        "expected_vulnerable_behavior": "One identity receives another identity's object.",
        "expected_secure_behavior": "The object is denied across identities.",
        "potential_impact": "Unauthorized data exposure.",
        "confidence": 0.4,
        "supporting_evidence_ids": [observation_id],
        "contradicting_evidence_ids": [],
    }, headers=auth_headers())
    assert hypothesis.status_code == 201, hypothesis.text
    hypothesis_id = hypothesis.json()["id"]

    investigating = client.post(f"/hypotheses/{hypothesis_id}/status", json={"status": "investigating"}, headers=auth_headers())
    assert investigating.status_code == 200

    proposal = client.post(f"/investigations/{investigation_id}/proposals", json={
        "hypothesis_id": hypothesis_id,
        "action": "offline_analysis",
        "rationale": "Compare the imported observation against expected behavior.",
        "budget_units": 2,
        "iteration_units": 1,
        "evidence_ids": [observation_id],
    }, headers=auth_headers())
    assert proposal.status_code == 201, proposal.text

    reviewed = client.post(f"/proposals/{proposal.json()['id']}/review", json={"status": "accepted"}, headers=auth_headers())
    assert reviewed.status_code == 200, reviewed.text

    disproved = client.post(f"/hypotheses/{hypothesis_id}/status", json={"status": "disproved"}, headers=auth_headers())
    assert disproved.status_code == 200


def test_proposal_cannot_exceed_investigation_budget(client):
    project = create_project(client)
    task = authorize_task(client, project["id"])
    assert client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers()).status_code == 200
    investigation = client.post(f"/tasks/{task['id']}/investigations", headers=auth_headers())
    assert investigation.status_code == 201
    observation_id = import_observation(client, project["id"])
    investigation_id = investigation.json()["id"]

    hypothesis = client.post(f"/investigations/{investigation_id}/hypotheses", json={
        "category": "api.authorization",
        "statement": "A test hypothesis.",
        "expected_vulnerable_behavior": "Vulnerable behavior.",
        "expected_secure_behavior": "Secure behavior.",
        "potential_impact": "Potential impact.",
        "confidence": 0.5,
        "supporting_evidence_ids": [observation_id],
    }, headers=auth_headers())
    assert hypothesis.status_code == 201

    proposal = client.post(f"/investigations/{investigation_id}/proposals", json={
        "hypothesis_id": hypothesis.json()["id"],
        "action": "offline_analysis",
        "rationale": "A bounded offline proposal.",
        "budget_units": 6,
        "iteration_units": 1,
        "evidence_ids": [observation_id],
    }, headers=auth_headers())
    assert proposal.status_code == 409


def test_unowned_evidence_cannot_support_hypothesis(client):
    project = create_project(client)
    task = authorize_task(client, project["id"])
    assert client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers()).status_code == 200
    investigation = client.post(f"/tasks/{task['id']}/investigations", headers=auth_headers())
    assert investigation.status_code == 201

    hypothesis = client.post(f"/investigations/{investigation.json()['id']}/hypotheses", json={
        "category": "api.authorization",
        "statement": "A test hypothesis.",
        "expected_vulnerable_behavior": "Vulnerable behavior.",
        "expected_secure_behavior": "Secure behavior.",
        "potential_impact": "Potential impact.",
        "confidence": 0.5,
        "supporting_evidence_ids": ["00000000-0000-0000-0000-000000000000"],
    }, headers=auth_headers())
    assert hypothesis.status_code == 404
