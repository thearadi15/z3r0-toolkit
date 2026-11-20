from datetime import datetime, timedelta, timezone


def headers():
    return {"X-API-Token": "test-token"}


def setup_investigation(client):
    project = client.post("/projects", json={
        "name": "validation-test",
        "budget_limit_units": 20,
        "iteration_limit": 10,
        "scopes": [{"host": "example.com", "scheme": "https", "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}],
    }, headers=headers())
    assert project.status_code == 201
    project_id = project.json()["id"]

    task = client.post(f"/projects/{project_id}/tasks", json={
        "action": "offline_analysis", "target_url": "https://example.com/source",
        "objective": "Offline validation test.", "requested_budget_units": 3, "requested_iterations": 2,
    }, headers=headers())
    assert task.status_code == 201
    authorized = client.post(f"/tasks/{task.json()['id']}/authorize", headers=headers())
    assert authorized.status_code == 200
    investigation = client.post(f"/tasks/{task.json()['id']}/investigations", headers=headers())
    assert investigation.status_code == 201

    artifact = client.post(f"/projects/{project_id}/evidence", json={
        "schema_version": "1", "source_tool": "fixture", "run_status": "partial",
        "observations": [
            {"kind": "finding_candidate", "subject": "https://example.com/api/items", "data": {"claim": "candidate"}},
            {"kind": "endpoint", "subject": "https://example.com/api/items", "data": {"method": "GET", "independent_result": "denied"}},
        ],
    }, headers=headers())
    assert artifact.status_code == 201
    observations = artifact.json()["observations"]
    return investigation.json()["id"], observations


def test_finding_cannot_be_validated_without_independent_confirmation(client):
    investigation_id, observations = setup_investigation(client)
    finding = client.post(f"/investigations/{investigation_id}/findings", json={
        "title": "Candidate authorization weakness",
        "category": "api.authorization",
        "statement": "An object may be returned across identities.",
        "impact": "Potential unauthorized data exposure.",
        "severity": "high",
        "evidence_ids": [observations[0]["id"]],
    }, headers=headers())
    assert finding.status_code == 201, finding.text
    finding_id = finding.json()["id"]

    review = client.post(f"/findings/{finding_id}/review", json={"status": "validated"}, headers=headers())
    assert review.status_code == 409


def test_reproducible_independent_confirmation_allows_human_review(client):
    investigation_id, observations = setup_investigation(client)
    finding = client.post(f"/investigations/{investigation_id}/findings", json={
        "title": "Candidate authorization weakness",
        "category": "api.authorization",
        "statement": "An object may be returned across identities.",
        "impact": "Potential unauthorized data exposure.",
        "severity": "high",
        "evidence_ids": [observations[0]["id"]],
    }, headers=headers())
    finding_id = finding.json()["id"]

    validation = client.post(f"/findings/{finding_id}/validations", json={
        "verdict": "confirmed",
        "summary": "A separate identity observed the protected object.",
        "reproducible": True,
        "supporting_evidence_ids": [observations[1]["id"]],
        "contradicting_evidence_ids": [],
    }, headers=headers())
    assert validation.status_code == 201, validation.text

    review = client.post(f"/findings/{finding_id}/review", json={"status": "validated"}, headers=headers())
    assert review.status_code == 200, review.text
    assert review.json()["status"] == "validated"


def test_rejected_validation_is_not_confirmed(client):
    investigation_id, observations = setup_investigation(client)
    finding = client.post(f"/investigations/{investigation_id}/findings", json={
        "title": "Candidate weakness", "category": "authorization", "statement": "A candidate.",
        "impact": "Unknown.", "severity": "medium", "evidence_ids": [observations[0]["id"]],
    }, headers=headers())
    finding_id = finding.json()["id"]

    validation = client.post(f"/findings/{finding_id}/validations", json={
        "verdict": "rejected", "summary": "Secure behavior was independently reproduced.",
        "reproducible": True, "supporting_evidence_ids": [observations[1]["id"]],
    }, headers=headers())
    assert validation.status_code == 201

    denied = client.post(f"/findings/{finding_id}/review", json={"status": "validated"}, headers=headers())
    assert denied.status_code == 409

    rejected = client.post(f"/findings/{finding_id}/review", json={"status": "rejected"}, headers=headers())
    assert rejected.status_code == 200


def test_unowned_validation_evidence_is_rejected(client):
    investigation_id, observations = setup_investigation(client)
    finding = client.post(f"/investigations/{investigation_id}/findings", json={
        "title": "Candidate weakness", "category": "authorization", "statement": "A candidate.",
        "impact": "Unknown.", "severity": "medium", "evidence_ids": [observations[0]["id"]],
    }, headers=headers())
    finding_id = finding.json()["id"]
    response = client.post(f"/findings/{finding_id}/validations", json={
        "verdict": "confirmed", "summary": "Independent fixture.", "reproducible": True,
        "supporting_evidence_ids": ["00000000-0000-0000-0000-000000000000"],
    }, headers=headers())
    assert response.status_code == 404
