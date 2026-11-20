from datetime import datetime, timedelta, timezone

import httpx


def auth_headers():
    return {"X-API-Token": "test-token"}


def create_authorized_http_task(client):
    project = client.post("/projects", json={
        "name": "http-gateway-test",
        "budget_limit_units": 20,
        "iteration_limit": 10,
        "scopes": [{
            "host": "example.com",
            "scheme": "https",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        }],
    }, headers=auth_headers())
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    task = client.post(f"/projects/{project_id}/tasks", json={
        "action": "http_request",
        "target_url": "https://example.com/api/items",
        "objective": "Execute one bounded fixture request.",
        "requested_budget_units": 3,
        "requested_iterations": 2,
    }, headers=auth_headers())
    assert task.status_code == 201, task.text
    task_id = task.json()["id"]

    approval = client.post(f"/tasks/{task_id}/approvals", json={
        "max_budget_units": 3,
        "max_iterations": 2,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }, headers=auth_headers())
    assert approval.status_code == 201, approval.text
    authorized = client.post(f"/tasks/{task_id}/authorize", headers=auth_headers())
    assert authorized.status_code == 200, authorized.text
    return task_id


def test_authorized_http_request_persists_redacted_evidence(client):
    task_id = create_authorized_http_task(client)

    def handler(request):
        return httpx.Response(200, headers={"Content-Type": "text/plain", "Set-Cookie": "session=secret"}, content=b"fixture-response")

    client.app.state.http_transport = httpx.MockTransport(handler)
    response = client.post(f"/tasks/{task_id}/http-execute", json={
        "method": "GET",
        "url": "https://example.com/api/items",
        "headers": {"Accept": "text/plain"},
        "timeout_ms": 5000,
        "max_response_bytes": 1024,
    }, headers=auth_headers())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status_code"] == 200
    assert body["outcome"] == "completed"
    assert body["response_bytes"] == len(b"fixture-response")
    assert len(body["response_sha256"] or "") == 64

    with client.app.state.session_factory() as session:
        from z3r0_platform.models import HttpExecution
        stored = session.query(HttpExecution).one()
        assert stored.response_headers["set-cookie"] == "[REDACTED]"


def test_redirect_is_never_followed(client):
    task_id = create_authorized_http_task(client)

    def handler(request):
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    client.app.state.http_transport = httpx.MockTransport(handler)
    response = client.post(f"/tasks/{task_id}/http-execute", json={
        "method": "GET",
        "url": "https://example.com/api/items",
    }, headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["outcome"] == "redirect_blocked"
    assert response.json()["redirect_count"] == 1


def test_sensitive_headers_and_out_of_scope_urls_are_rejected(client):
    task_id = create_authorized_http_task(client)
    response = client.post(f"/tasks/{task_id}/http-execute", json={
        "method": "GET",
        "url": "https://example.com/api/items",
        "headers": {"Authorization": "Bearer secret"},
    }, headers=auth_headers())
    assert response.status_code == 422

    response = client.post(f"/tasks/{task_id}/http-execute", json={
        "method": "GET",
        "url": "https://outside.example/api/items",
    }, headers=auth_headers())
    assert response.status_code == 403


def test_http_iteration_limit_is_enforced(client):
    task_id = create_authorized_http_task(client)
    client.app.state.http_transport = httpx.MockTransport(lambda request: httpx.Response(204))
    for _ in range(2):
        response = client.post(f"/tasks/{task_id}/http-execute", json={
            "method": "GET",
            "url": "https://example.com/api/items",
        }, headers=auth_headers())
        assert response.status_code == 200

    denied = client.post(f"/tasks/{task_id}/http-execute", json={
        "method": "GET",
        "url": "https://example.com/api/items",
    }, headers=auth_headers())
    assert denied.status_code == 409
    assert "iteration" in denied.json()["detail"]


def test_curl_export_is_safe_and_never_executes(client):
    task_id = create_authorized_http_task(client)
    response = client.post(f"/tasks/{task_id}/curl-export", json={
        "method": "POST",
        "url": "https://example.com/api/items",
        "headers": {"Accept": "application/json"},
        "body": '{"name":"fixture"}',
    }, headers=auth_headers())
    assert response.status_code == 200
    command = response.json()["command"]
    assert command.startswith("curl ")
    assert "Accept: application/json" in command
    assert "--max-redirs 0" in command
