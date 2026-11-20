from datetime import datetime, timedelta, timezone


def headers():
    return {"X-API-Token": "test-token"}


def setup_investigation(client):
    project = client.post("/projects", json={"name":"remaining-test","budget_limit_units":20,"iteration_limit":10,"scopes":[{"host":"example.com","scheme":"https","expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()}]}, headers=headers())
    assert project.status_code == 201
    project_id = project.json()["id"]
    task = client.post(f"/projects/{project_id}/tasks", json={"action":"offline_analysis","target_url":"https://example.com/source","objective":"Offline research.","requested_budget_units":3,"requested_iterations":2}, headers=headers())
    assert task.status_code == 201
    assert client.post(f"/tasks/{task.json()['id']}/authorize", headers=headers()).status_code == 200
    investigation = client.post(f"/tasks/{task.json()['id']}/investigations", headers=headers())
    assert investigation.status_code == 201
    return project_id, investigation.json()["id"]


def test_advisory_and_source_claims_remain_candidates(client):
    project_id, investigation_id = setup_investigation(client)
    imported = client.post(f"/projects/{project_id}/evidence", json={"schema_version":"1","source_tool":"fixture","run_status":"partial","observations":[{"kind":"note","subject":"fixture evidence","data":{"claim":"offline only"}}]}, headers=headers())
    evidence_id = imported.json()["observations"][0]["id"]
    advisory = client.post(f"/investigations/{investigation_id}/advisories", json={"advisory_id":"CVE-2026-0001","package_name":"fixture","affected_version":"1.0.0","source_name":"fixture-feed","source_digest":"a"*64,"retrieved_at":datetime.now(timezone.utc).isoformat(),"evidence_ids":[evidence_id]}, headers=headers())
    assert advisory.status_code == 201
    assert advisory.json()["status"] == "candidate"

    claim = client.post(f"/investigations/{investigation_id}/source-claims", json={"repository":"https://example.invalid/repo","revision":"deadbeef","claim_type":"patch","file_path":"src/app.py","line_start":10,"line_end":20,"statement":"A caller-selected fixture claim.","evidence_digest":"b"*64}, headers=headers())
    assert claim.status_code == 201
    assert claim.json()["status"] == "candidate"


def test_safe_poc_requires_validated_finding_and_does_not_execute(client):
    _, investigation_id = setup_investigation(client)
    evidence = client.post(f"/projects/{client.get('/projects/' + ''.join([])).text if False else 'missing'}/evidence") if False else None

    artifact_project = client.get("/projects") if False else None
    project_id = client.app.state.session_factory
    with project_id() as session:
        from z3r0_platform.models import Project
        project = session.query(Project).filter(Project.owner_id == "test-operator").first()
        project_id = project.id

    imported = client.post(f"/projects/{project_id}/evidence", json={"schema_version":"1","source_tool":"fixture","run_status":"partial","observations":[{"kind":"finding_candidate","subject":"fixture","data":{"claim":"candidate"}}]}, headers=headers())
    observation_id = imported.json()["observations"][0]["id"]
    finding = client.post(f"/investigations/{investigation_id}/findings", json={"title":"Fixture finding","category":"fixture","statement":"Fixture.","impact":"Fixture.","severity":"low","evidence_ids":[observation_id]}, headers=headers())
    finding_id = finding.json()["id"]

    denied = client.post(f"/findings/{finding_id}/pocs", json={"title":"Fixture PoC","format":"http","content":"GET /fixture","approved_target":"https://example.com/fixture"}, headers=headers())
    assert denied.status_code == 409


def test_report_and_research_profile_are_persisted_without_workers(client):
    project_id, investigation_id = setup_investigation(client)
    artifact_project = project_id
    imported = client.post(f"/projects/{artifact_project}/evidence", json={"schema_version":"1","source_tool":"fixture","run_status":"partial","observations":[{"kind":"note","subject":"fixture evidence","data":{"claim":"offline only"}}]}, headers=headers())
    evidence_id = imported.json()["observations"][0]["id"]
    report = client.post(f"/investigations/{investigation_id}/reports", json={"title":"Fixture report","summary":"Candidate-only report.","limitations":"No external validation.","evidence_ids":[evidence_id]}, headers=headers())
    assert report.status_code == 201
    assert report.json()["finding_count"] == 0

    profile = client.post(f"/projects/{project_id}/research-profiles", json={"name":"bounded-fixture","cpu_limit_percent":10,"memory_limit_mb":512,"wall_time_seconds":60,"process_limit":2,"storage_limit_mb":256}, headers=headers())
    assert profile.status_code == 201
    assert profile.json()["status"] == "inactive"
    assert profile.json()["worker_enabled"] is False
