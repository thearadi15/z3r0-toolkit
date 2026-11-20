from z3r0_platform.models import EvidenceArtifact, EvidenceObservation
from z3r0_platform.schemas import EvidenceObservationInput
from pydantic import ValidationError


def evidence_payload(**overrides):
    payload = {
        "schema_version": "1",
        "source_tool": "fixture-importer",
        "source_version": "1.2",
        "artifact_name": "run.json",
        "run_status": "partial",
        "coverage_note": "Only the first page was imported.",
        "observations": [
            {
                "kind": "endpoint",
                "subject": "https://example.com/api/items",
                "source_record_id": "row-1",
                "data": {
                    "method": "GET",
                    "status_code": 200,
                    "request_headers": {"Authorization": "Bearer example-secret"},
                    "url": "https://example.com/api/items?token=example-secret",
                },
            }
        ],
    }
    payload.update(overrides)
    return payload


def test_evidence_import_preserves_provenance_hash_and_partial_status(
    client, create_project
):
    project = create_project().json()
    response = client.post(
        f"/projects/{project['id']}/evidence",
        json=evidence_payload(),
        headers={"X-API-Token": "test-token"},
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["duplicate"] is False
    assert result["artifact"]["source_tool"] == "fixture-importer"
    assert result["artifact"]["source_version"] == "1.2"
    assert result["artifact"]["run_status"] == "partial"
    assert result["artifact"]["record_count"] == 1
    assert len(result["artifact"]["payload_sha256"]) == 64

    observation = result["observations"][0]
    assert observation["source_record_id"] == "row-1"
    assert observation["kind"] == "endpoint"
    assert len(observation["record_sha256"]) == 64
    assert observation["data"]["request_headers"]["Authorization"] == "[REDACTED]"
    assert observation["data"]["url"].endswith("?token=[REDACTED]")
    assert result["artifact"]["redacted_field_count"] == 2


def test_identical_evidence_import_is_idempotent(client, create_project):
    project = create_project().json()
    headers = {"X-API-Token": "test-token"}
    first = client.post(
        f"/projects/{project['id']}/evidence", json=evidence_payload(), headers=headers
    )
    second = client.post(
        f"/projects/{project['id']}/evidence", json=evidence_payload(), headers=headers
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["artifact"]["id"] == second.json()["artifact"]["id"]
    assert second.json()["duplicate"] is True
    with client.app.state.session_factory() as session:
        assert session.query(EvidenceArtifact).count() == 1
        assert session.query(EvidenceObservation).count() == 1


def test_evidence_can_be_listed_and_fetched_within_project_owner_scope(
    client, create_project
):
    project = create_project().json()
    headers = {"X-API-Token": "test-token"}
    imported = client.post(
        f"/projects/{project['id']}/evidence", json=evidence_payload(), headers=headers
    ).json()

    listed = client.get(f"/projects/{project['id']}/evidence", headers=headers)
    fetched = client.get(f"/evidence/{imported['artifact']['id']}", headers=headers)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [imported["artifact"]["id"]]
    assert fetched.status_code == 200
    assert fetched.json()["observations"][0]["source_record_id"] == "row-1"

    missing = client.get("/evidence/not-an-owned-artifact", headers=headers)
    assert missing.status_code == 404


def test_evidence_import_rejects_unknown_schema_and_unsupported_fields(
    client, create_project
):
    project = create_project().json()
    payload = evidence_payload(schema_version="2")
    response = client.post(
        f"/projects/{project['id']}/evidence",
        json=payload,
        headers={"X-API-Token": "test-token"},
    )
    assert response.status_code == 422

    try:
        EvidenceObservationInput.model_validate(
            {
                "kind": "note",
                "subject": "offline import",
                "data": {"unexpected": float("nan")},
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("non-JSON float values must be rejected")


def test_evidence_import_requires_operator_token(client, create_project):
    project = create_project().json()
    response = client.post(
        f"/projects/{project['id']}/evidence", json=evidence_payload()
    )
    assert response.status_code == 401
