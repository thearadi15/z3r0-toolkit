from datetime import datetime, timedelta, timezone


def auth_headers():
    return {"X-API-Token": "test-token"}


def create_project(client):
    response = client.post("/projects", json={
        "name": "intelligence-test",
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


def import_evidence(client, project_id, observations):
    response = client.post(f"/projects/{project_id}/evidence", json={
        "schema_version": "1",
        "source_tool": "offline-fixture",
        "run_status": "partial",
        "observations": observations,
    }, headers=auth_headers())
    assert response.status_code == 201, response.text


def test_rebuild_normalizes_endpoints_and_keeps_openapi_origin_unknown(client):
    project = create_project(client)
    import_evidence(client, project["id"], [
        {"kind": "endpoint", "subject": "https://example.com/api/items", "data": {"method": "GET", "parameters": [{"name": "id", "in": "query"}]}},
        {"kind": "endpoint", "subject": "https://example.com/api/items", "data": {"method": "GET", "status_code": 200}},
        {"kind": "api_operation", "subject": "POST /api/items", "data": {"method": "POST", "parameters": [{"name": "body", "in": "body"}], "security_requirement_declared": True}},
        {"kind": "finding_candidate", "subject": "https://example.com/api/admin", "data": {"template_id": "fixture"}},
        {"kind": "endpoint", "subject": "https://outside.example/net", "data": {"method": "GET"}},
    ])

    rebuilt = client.post(f"/projects/{project['id']}/intelligence/rebuild", headers=auth_headers())
    assert rebuilt.status_code == 200, rebuilt.text
    assert rebuilt.json()["endpoint_count"] == 3

    endpoints = client.get(f"/projects/{project['id']}/intelligence/endpoints", headers=auth_headers())
    assert endpoints.status_code == 200
    rows = endpoints.json()
    get_row = next(row for row in rows if row["method"] == "GET" and row["path"] == "/api/items")
    assert get_row["host"] == "example.com"
    assert get_row["origin_declared"] is True
    assert get_row["evidence_count"] == 2

    post_row = next(row for row in rows if row["method"] == "POST" and row["path"] == "/api/items")
    assert post_row["host"] is None
    assert post_row["origin_declared"] is False

    assert all(row["host"] != "outside.example" for row in rows)


def test_rebuild_is_repeatable_and_idempotent(client):
    project = create_project(client)
    observations = [{"kind": "technology", "subject": "example.com", "data": {"name": "Nginx"}}]
    import_evidence(client, project["id"], observations)

    first = client.post(f"/projects/{project['id']}/intelligence/rebuild", headers=auth_headers())
    second = client.post(f"/projects/{project['id']}/intelligence/rebuild", headers=auth_headers())
    assert first.status_code == 200
    assert second.status_code == 200

    assets = client.get(f"/projects/{project['id']}/intelligence/assets", headers=auth_headers())
    assert assets.status_code == 200
    assert len(assets.json()) == 1
    assert assets.json()[0]["host"] == "example.com"


def test_intelligence_is_project_scoped(client):
    first = create_project(client)
    second = client.post("/projects", json={
        "name": "other",
        "budget_limit_units": 10,
        "iteration_limit": 5,
        "scopes": [{"host": "other.example", "scheme": "https", "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}],
    }, headers=auth_headers()).json()

    import_evidence(client, first["id"], [{"kind": "endpoint", "subject": "https://example.com/private", "data": {"method": "GET"}}])
    client.post(f"/projects/{first['id']}/intelligence/rebuild", headers=auth_headers())

    endpoint_rows = client.get(f"/projects/{second['id']}/intelligence/endpoints", headers=auth_headers())
    assert endpoint_rows.status_code == 200
    assert endpoint_rows.json() == []
