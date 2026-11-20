import hashlib
import json

from pydantic import ValidationError

from z3r0_platform.models import EvidenceArtifact, EvidenceObservation
from z3r0_platform.schemas import EvidenceSourceImport


def auth_headers():
    return {"X-API-Token": "test-token"}


def test_nuclei_jsonl_is_imported_as_unverified_candidate_with_source_digest(
    client, create_project
):
    project = create_project().json()
    record = {
        "template-id": "example-template",
        "type": "http",
        "host": "https://example.com",
        "matched-at": "https://example.com/item?token=sample-secret",
        "matcher-name": "exposure-check",
        "timestamp": "2026-11-17T00:00:00Z",
        "info": {
            "name": "Scanner alert",
            "severity": "medium",
            "tags": ["test"],
        },
        "request": "sensitive request content",
        "response": "sensitive response content",
        "curl-command": "must not be imported",
    }
    source_text = json.dumps(record) + "\n"
    response = client.post(
        f"/projects/{project['id']}/evidence/import",
        json={
            "source_format": "nuclei-jsonl",
            "source_text": source_text,
            "run_status": "partial",
            "source_version": "3.4.1",
            "artifact_name": "nuclei-output.jsonl",
            "coverage_note": "The caller reported an incomplete run.",
        },
        headers=auth_headers(),
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["artifact"]["source_tool"] == "nuclei"
    assert result["artifact"]["source_version"] == "3.4.1"
    assert result["artifact"]["run_status"] == "partial"
    assert result["artifact"]["source_sha256"] == hashlib.sha256(
        source_text.encode("utf-8")
    ).hexdigest()
    assert len(result["observations"]) == 1
    observation = result["observations"][0]
    assert observation["kind"] == "finding_candidate"
    assert observation["subject"].endswith("?token=[REDACTED]")
    assert observation["source_record_id"] == "line:1"
    assert observation["data"]["scanner_severity"] == "medium"
    assert "request" not in observation["data"]
    assert "response" not in observation["data"]
    assert "curl-command" not in observation["data"]


def test_openapi_json_imports_declared_operations_and_retains_unresolved_refs(
    client, create_project
):
    project = create_project().json()
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://should-not-be-requested.invalid"}],
        "paths": {
            "/users/{user_id}": {
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "get": {
                    "operationId": "getUser",
                    "summary": "Read user",
                    "tags": ["users"],
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"$ref": "#/components/parameters/TraceId"},
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        },
                    ],
                    "responses": {
                        "200": {"$ref": "#/components/responses/User"},
                        "404": {"description": "Not found"},
                    },
                },
                "post": {
                    "requestBody": {"$ref": "#/components/requestBodies/User"},
                    "responses": {"201": {"description": "Created"}},
                },
            }
        },
    }
    response = client.post(
        f"/projects/{project['id']}/evidence/import",
        json={
            "source_format": "openapi-json",
            "source_text": json.dumps(document),
            "run_status": "complete",
            "artifact_name": "openapi.json",
        },
        headers=auth_headers(),
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["artifact"]["source_tool"] == "openapi"
    assert result["artifact"]["source_version"] == "3.1.0"
    assert len(result["observations"]) == 2
    get_operation = result["observations"][0]
    assert get_operation["subject"] == "GET /users/{user_id}"
    assert get_operation["data"]["security_requirement_declared"] is True
    assert get_operation["data"]["parameters"] == [
        {"name": "user_id", "in": "path", "required": True, "type": "integer"},
        {"unresolved_reference": "#/components/parameters/TraceId"},
    ]
    assert get_operation["data"]["unresolved_references"] == [
        "#/components/responses/User"
    ]
    post_operation = result["observations"][1]
    assert post_operation["subject"] == "POST /users/{user_id}"
    assert "#/components/requestBodies/User" in post_operation["data"]["unresolved_references"]


def test_format_import_is_idempotent_by_source_content(client, create_project):
    project = create_project().json()
    body = {
        "source_format": "nuclei-jsonl",
        "source_text": json.dumps(
            {"host": "https://example.com", "info": {"severity": "info"}}
        ),
        "run_status": "complete",
    }
    first = client.post(
        f"/projects/{project['id']}/evidence/import",
        json=body,
        headers=auth_headers(),
    )
    second = client.post(
        f"/projects/{project['id']}/evidence/import",
        json=body,
        headers=auth_headers(),
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["artifact"]["id"] == second.json()["artifact"]["id"]
    assert second.json()["duplicate"] is True
    with client.app.state.session_factory() as session:
        assert session.query(EvidenceArtifact).count() == 1
        assert session.query(EvidenceObservation).count() == 1


def test_malformed_nuclei_input_is_rejected_without_partial_import(client, create_project):
    project = create_project().json()
    response = client.post(
        f"/projects/{project['id']}/evidence/import",
        json={
            "source_format": "nuclei-jsonl",
            "source_text": '{"host":"https://example.com"}\n{bad json',
            "run_status": "partial",
        },
        headers=auth_headers(),
    )

    assert response.status_code == 422
    with client.app.state.session_factory() as session:
        assert session.query(EvidenceArtifact).count() == 0


def test_openapi_parser_does_not_accept_unresolved_path_item_references(
    client, create_project
):
    project = create_project().json()
    response = client.post(
        f"/projects/{project['id']}/evidence/import",
        json={
            "source_format": "openapi-json",
            "source_text": json.dumps(
                {"openapi": "3.0.0", "paths": {"/users": {"$ref": "#/paths/users"}}}
            ),
            "run_status": "complete",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 422
    assert "not dereferenced" in response.json()["detail"]


def test_source_import_limits_utf8_bytes_and_rejects_unknown_fields():
    try:
        EvidenceSourceImport.model_validate(
            {
                "source_format": "openapi-json",
                "source_text": "é" * 1_048_577,
                "run_status": "complete",
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("source text over the UTF-8 byte limit must be rejected")

    try:
        EvidenceSourceImport.model_validate(
            {
                "source_format": "openapi-json",
                "source_text": "{}",
                "run_status": "complete",
                "unexpected": True,
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("unknown source import fields must be rejected")
