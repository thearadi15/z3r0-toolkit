from datetime import datetime, timedelta, timezone


def auth_headers():
    return {"X-API-Token": "test-token"}


def create_authorized_browser_task(client):
    project = client.post("/projects", json={
        "name": "browser-gateway-test",
        "budget_limit_units": 20,
        "iteration_limit": 10,
        "scopes": [{"host": "example.com", "scheme": "https", "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}],
    }, headers=auth_headers())
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    task = client.post(f"/projects/{project_id}/tasks", json={
        "action": "browser_action",
        "target_url": "https://example.com/login",
        "objective": "Exercise a bounded browser scenario.",
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


class MockBrowserDriver:
    def execute(self, actions, scopes, allow_loopback):
        results = []
        final_url = None
        for ordinal, action in enumerate(actions):
            if action.action == "navigate":
                final_url = action.url
            results.append({"ordinal": ordinal, "action": action.action, "outcome": "completed", "detail": "text_ref_used" if action.action == "type" else None})
        return {"outcome": "completed", "actions": results, "blocked_requests": 0, "final_url": final_url}


def test_authorized_browser_scenario_is_persisted(client):
    task_id = create_authorized_browser_task(client)
    client.app.state.browser_driver = MockBrowserDriver()
    response = client.post(f"/tasks/{task_id}/browser-execute", json={
        "actions": [
            {"action": "navigate", "url": "https://example.com/login", "timeout_ms": 5000},
            {"action": "type", "selector": "#username", "text_ref": "Z3R0_TEST_USERNAME", "timeout_ms": 5000},
            {"action": "click", "selector": "button[type=submit]", "timeout_ms": 5000},
        ]
    }, headers=auth_headers())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "completed"
    assert body["final_url"] == "https://example.com/login"
    assert len(body["actions"]) == 3

    with client.app.state.session_factory() as session:
        from z3r0_platform.models import BrowserExecution
        stored = session.query(BrowserExecution).one()
        assert stored.action_count == 3
        assert "text_ref_used" in str(stored.actions)


def test_browser_rejects_out_of_scope_navigation(client):
    task_id = create_authorized_browser_task(client)
    client.app.state.browser_driver = MockBrowserDriver()
    response = client.post(f"/tasks/{task_id}/browser-execute", json={
        "actions": [{"action": "navigate", "url": "https://outside.example/page"}]
    }, headers=auth_headers())
    assert response.status_code == 403


def test_browser_rejects_missing_type_reference(client):
    task_id = create_authorized_browser_task(client)
    response = client.post(f"/tasks/{task_id}/browser-execute", json={
        "actions": [{"action": "type", "selector": "#username"}]
    }, headers=auth_headers())
    assert response.status_code == 422


def test_browser_iteration_limit_is_enforced(client):
    task_id = create_authorized_browser_task(client)
    client.app.state.browser_driver = MockBrowserDriver()
    scenario = {"actions": [{"action": "navigate", "url": "https://example.com/login"}]}
    assert client.post(f"/tasks/{task_id}/browser-execute", json=scenario, headers=auth_headers()).status_code == 200
    assert client.post(f"/tasks/{task_id}/browser-execute", json=scenario, headers=auth_headers()).status_code == 200
    denied = client.post(f"/tasks/{task_id}/browser-execute", json=scenario, headers=auth_headers())
    assert denied.status_code == 409
