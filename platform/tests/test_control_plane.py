from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy import update

from z3r0_platform.database import make_engine, make_session_factory
from z3r0_platform.models import AuditEvent, Project, ScopeEntry


def auth_headers():
    return {"X-API-Token": "test-token"}


def create_task(client, project_id, payload):
    response = client.post(
        f"/projects/{project_id}/tasks", json=payload, headers=auth_headers()
    )
    assert response.status_code == 201, response.text
    return response.json()


def approve_task(client, task_id, budget=5, iterations=2, days=1):
    response = client.post(
        f"/tasks/{task_id}/approvals",
        json={
            "max_budget_units": budget,
            "max_iterations": iterations,
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(),
        },
        headers=auth_headers(),
    )
    return response


def test_api_is_closed_without_token_and_health_is_available(client):
    assert client.get("/health").status_code == 200
    response = client.post("/projects", json={})
    assert response.status_code == 401


def test_project_creation_persists_explicit_scope_and_owner(create_project):
    response = create_project()
    assert response.status_code == 201, response.text
    project = response.json()
    assert project["owner_id"] == "test-operator"
    assert project["scopes"][0]["host"] == "example.com"
    assert project["budget_reserved_units"] == 0


def test_active_task_requires_bound_operator_approval(
    client, create_project, task_payload
):
    project = create_project().json()
    task = create_task(client, project["id"], task_payload)
    denied = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert denied.status_code == 409
    assert "approval" in denied.json()["detail"]

    approval = approve_task(client, task["id"])
    assert approval.status_code == 201, approval.text
    authorized = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["status"] == "authorized"
    assert authorized.json()["authorized_at"] is not None


def test_approval_cannot_exceed_task_limits(client, create_project, task_payload):
    project = create_project().json()
    task = create_task(client, project["id"], task_payload)
    response = approve_task(client, task["id"], budget=6)
    assert response.status_code == 422


def test_revoked_approval_cannot_authorize_task(client, create_project, task_payload):
    project = create_project().json()
    task = create_task(client, project["id"], task_payload)
    approval = approve_task(client, task["id"])
    assert approval.status_code == 201
    revoked = client.post(
        f"/approvals/{approval.json()['id']}/revoke", headers=auth_headers()
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers()).status_code == 409


def test_scope_is_rechecked_before_authorization(client, create_project):
    project = create_project().json()
    task = create_task(
        client,
        project["id"],
        {
            "action": "offline_analysis",
            "target_url": "https://example.com/source",
            "objective": "Analyze caller-supplied local source metadata.",
            "requested_budget_units": 2,
            "requested_iterations": 1,
        },
    )
    with client.app.state.session_factory() as session:
        session.execute(
            update(ScopeEntry)
            .where(ScopeEntry.project_id == project["id"])
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        session.commit()

    response = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert response.status_code == 409
    assert "scope" in response.json()["detail"]


def test_budget_and_iteration_reservation_is_atomic_and_audited(
    client, create_project, task_payload
):
    project = create_project(
        {
            "name": "bounded",
            "budget_limit_units": 8,
            "iteration_limit": 3,
            "scopes": [
                {
                    "host": "example.com",
                    "scheme": "https",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                }
            ],
        }
    ).json()
    first = create_task(client, project["id"], task_payload)
    assert approve_task(client, first["id"], budget=5, iterations=2).status_code == 201
    assert client.post(f"/tasks/{first['id']}/authorize", headers=auth_headers()).status_code == 200

    second_payload = {**task_payload, "requested_budget_units": 4, "requested_iterations": 1}
    second = create_task(client, project["id"], second_payload)
    assert approve_task(client, second["id"], budget=4, iterations=1).status_code == 201
    denied = client.post(f"/tasks/{second['id']}/authorize", headers=auth_headers())
    assert denied.status_code == 409
    assert "budget" in denied.json()["detail"]

    refreshed = client.get(f"/projects/{project['id']}", headers=auth_headers()).json()
    assert refreshed["budget_reserved_units"] == 5
    assert refreshed["iterations_reserved"] == 2
    audit = client.get(f"/projects/{project['id']}/audit", headers=auth_headers()).json()
    assert any(event["action"] == "task.authorized" and event["outcome"] == "denied" for event in audit)


def test_passive_task_is_budgeted_but_not_executed(client, create_project):
    project = create_project().json()
    task = create_task(
        client,
        project["id"],
        {
            "action": "offline_analysis",
            "target_url": "https://example.com/source",
            "objective": "Analyze caller-supplied local source metadata.",
            "requested_budget_units": 2,
            "requested_iterations": 1,
        },
    )
    response = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["status"] == "authorized"
    assert client.post(f"/tasks/{task['id']}/execute", headers=auth_headers()).status_code == 404


def test_project_data_is_hidden_from_other_operator(client):
    project = Project(
        owner_id="different-operator",
        name="private project",
        budget_limit_units=10,
        iteration_limit=5,
    )
    with client.app.state.session_factory() as session:
        session.add(project)
        session.commit()

    response = client.get(f"/projects/{project.id}", headers=auth_headers())
    assert response.status_code == 404


def test_reauthorizing_a_task_does_not_double_reserve(client, create_project, task_payload):
    project = create_project().json()
    task = create_task(client, project["id"], task_payload)
    assert approve_task(client, task["id"]).status_code == 201
    assert client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers()).status_code == 200
    repeated = client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers())
    assert repeated.status_code == 409
    project_state = client.get(f"/projects/{project['id']}", headers=auth_headers()).json()
    assert project_state["budget_reserved_units"] == task_payload["requested_budget_units"]
    assert project_state["iterations_reserved"] == task_payload["requested_iterations"]


def test_audit_and_budget_survive_engine_restart(client, create_project, task_payload):
    project = create_project().json()
    task = create_task(client, project["id"], task_payload)
    assert approve_task(client, task["id"]).status_code == 201
    assert client.post(f"/tasks/{task['id']}/authorize", headers=auth_headers()).status_code == 200

    engine_url = str(client.app.state.engine.url)
    restarted_engine = make_engine(engine_url)
    restarted_sessions = make_session_factory(restarted_engine)
    with restarted_sessions() as session:
        stored_project = session.scalar(select(Project).where(Project.id == project["id"]))
        assert stored_project.budget_reserved_units == 5
        assert session.scalar(
            select(AuditEvent).where(
                AuditEvent.project_id == project["id"], AuditEvent.action == "task.authorized"
            )
        )
    restarted_engine.dispose()
