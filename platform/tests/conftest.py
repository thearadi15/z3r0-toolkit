from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from z3r0_platform.api import create_app
from z3r0_platform.config import Settings
from z3r0_platform.database import make_engine
from z3r0_platform.models import Base


@pytest.fixture
def operator_id() -> str:
    return "test-operator"


@pytest.fixture
def client(tmp_path, operator_id):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    app = create_app(Settings(api_token="test-token", operator_id=operator_id, allow_loopback=True), engine)
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()


def future_iso(days: int = 1) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.fixture
def future_iso_factory():
    return future_iso


def project_payload(host: str = "example.com", **overrides):
    payload = {
        "name": "authorized assessment",
        "budget_limit_units": 20,
        "iteration_limit": 10,
        "scopes": [
            {
                "host": host,
                "scheme": "https",
                "include_subdomains": False,
                "expires_at": future_iso(),
            }
        ],
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def create_project(client):
    def create(payload=None):
        response = client.post(
            "/projects",
            json=payload or project_payload(),
            headers={"X-API-Token": "test-token"},
        )
        return response

    return create


@pytest.fixture
def task_payload(future_iso_factory):
    return {
        "action": "http_request",
        "target_url": "https://example.com/api/items",
        "objective": "Review the explicitly authorized endpoint behavior.",
        "requested_budget_units": 5,
        "requested_iterations": 2,
    }
