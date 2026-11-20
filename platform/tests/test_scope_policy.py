from datetime import datetime, timedelta, timezone

from z3r0_platform.schemas import normalize_host, normalize_target_url


def test_host_normalization_handles_case_idna_and_ip_literals():
    assert normalize_host("ExAmPle.COM.") == "example.com"
    assert normalize_host("bücher.example") == "xn--bcher-kva.example"
    assert normalize_host("2001:0db8::1") == "2001:db8::1"


def test_target_url_normalization_preserves_nondefault_port_and_path():
    assert normalize_target_url("HTTPS://Example.COM:8443/api")[0] == (
        "https://example.com:8443/api"
    )
    assert normalize_target_url("https://[2001:db8::1]/")[0] == "https://[2001:db8::1]/"


def test_invalid_target_url_shapes_are_rejected():
    invalid_urls = [
        "example.com",
        "ftp://example.com/",
        "https://user:pass@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "https://example.com:/",
        "https://example.com\\@evil.test/",
        "https://example.com:0/",
    ]
    for value in invalid_urls:
        try:
            normalize_target_url(value)
        except ValueError:
            continue
        raise AssertionError(f"expected rejection for {value!r}")


def test_scope_creation_requires_timezone_and_future_expiry(client):
    base = {
        "name": "invalid scope",
        "budget_limit_units": 3,
        "iteration_limit": 2,
        "scopes": [
            {
                "host": "example.com",
                "scheme": "https",
                "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            }
        ],
    }
    response = client.post(
        "/projects", json=base, headers={"X-API-Token": "test-token"}
    )
    assert response.status_code == 422


def test_project_requires_at_least_one_explicit_scope(client):
    response = client.post(
        "/projects",
        json={
            "name": "no scope",
            "budget_limit_units": 3,
            "iteration_limit": 2,
            "scopes": [],
        },
        headers={"X-API-Token": "test-token"},
    )
    assert response.status_code == 422


def test_project_rejects_duplicate_scope_entries(client, future_iso_factory):
    scope = {
        "host": "example.com",
        "scheme": "https",
        "expires_at": future_iso_factory(),
    }
    response = client.post(
        "/projects",
        json={
            "name": "duplicate scopes",
            "budget_limit_units": 3,
            "iteration_limit": 2,
            "scopes": [scope, scope],
        },
        headers={"X-API-Token": "test-token"},
    )
    assert response.status_code == 422


def test_scope_matching_rejects_suffix_tricks_and_unlisted_ports(client, create_project, task_payload):
    project = create_project().json()
    headers = {"X-API-Token": "test-token"}
    task_payload["target_url"] = "https://example.com.attacker.test/api"
    response = client.post(
        f"/projects/{project['id']}/tasks", json=task_payload, headers=headers
    )
    assert response.status_code == 403

    task_payload["target_url"] = "https://example.com:8443/api"
    response = client.post(
        f"/projects/{project['id']}/tasks", json=task_payload, headers=headers
    )
    assert response.status_code == 403


def test_subdomains_require_explicit_scope_flag(client, create_project, task_payload, future_iso_factory):
    project = create_project(
        {
            **{
                "name": "subdomains",
                "budget_limit_units": 10,
                "iteration_limit": 3,
            },
            "scopes": [
                {
                    "host": "example.com",
                    "scheme": "https",
                    "include_subdomains": True,
                    "expires_at": future_iso_factory(),
                }
            ],
        }
    ).json()
    task_payload["target_url"] = "https://api.example.com/v1"
    response = client.post(
        f"/projects/{project['id']}/tasks",
        json=task_payload,
        headers={"X-API-Token": "test-token"},
    )
    assert response.status_code == 201
