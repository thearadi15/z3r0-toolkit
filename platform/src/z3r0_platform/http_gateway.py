import hashlib
import ipaddress
import socket
import httpx

from sqlalchemy import select, func
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import HttpExecution, Project, ResearchTask, utc_now
from z3r0_platform.policy import ControlPlaneError, _audit, _find_scope, _has_valid_approval
from z3r0_platform.schemas import HttpRequestCreate

_SAFE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for name, value in headers.items():
        if name.lower() in {"set-cookie", "authorization", "proxy-authorization", "cookie", "x-api-key"}:
            redacted[name] = "[REDACTED]"
        else:
            redacted[name] = value
    return redacted


def resolve_host(host: str, port: int, allow_loopback: bool) -> list[str]:
    addresses: list[str] = []
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ControlPlaneError("target hostname could not be resolved", 502) from exc
    for family, _, _, _, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = sockaddr[0]
        if address in addresses:
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        blocked = parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified
        if blocked and not (allow_loopback and parsed.is_loopback):
            raise ControlPlaneError("resolved target address is outside the permitted network boundary", 403)
        addresses.append(address)
    if not addresses:
        raise ControlPlaneError("target hostname resolved to no usable address", 502)
    return addresses



def execute_authorized_http_request(
    session: Session,
    task_id: str,
    operator_id: str,
    spec: HttpRequestCreate,
    *,
    allow_loopback: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> HttpExecution:
    return _execute_http_request(session, task_id, operator_id, spec, allow_loopback, transport)


def _execute_http_request(
    session: Session,
    task_id: str,
    operator_id: str,
    spec: HttpRequestCreate,
    allow_loopback: bool,
    transport: httpx.BaseTransport | None,
) -> HttpExecution:
    task = session.scalar(
        select(ResearchTask)
        .join(Project)
        .where(ResearchTask.id == task_id, Project.owner_id == operator_id)
        .options(selectinload(ResearchTask.project).selectinload(Project.scopes), selectinload(ResearchTask.approvals))
    )
    if task is None:
        raise ControlPlaneError("task not found", 404)
    if task.status != "authorized":
        raise ControlPlaneError("task is not authorized", 409)
    if task.action != "http_request":
        raise ControlPlaneError("task action does not permit HTTP execution", 409)

    now = utc_now()
    scope = _find_scope(task.project.scopes, spec.url, at=now)
    if scope is None:
        raise ControlPlaneError("target URL is outside active project scope", 403)
    if not _has_valid_approval(task, now):
        raise ControlPlaneError("valid task-specific human approval is required", 409)

    counts = session.execute(
        select(func.count(HttpExecution.id), func.coalesce(func.sum(HttpExecution.request_bytes), 0))
        .where(HttpExecution.task_id == task.id)
    ).one()
    completed_requests = int(counts[0])
    if completed_requests + 1 > task.requested_budget_units:
        raise ControlPlaneError("task budget limit would be exceeded", 409)
    if completed_requests + 1 > task.requested_iterations:
        raise ControlPlaneError("task iteration limit would be exceeded", 409)

    from urllib.parse import urlsplit
    parts = urlsplit(spec.url)
    host = parts.hostname
    if host is None:
        raise ControlPlaneError("target URL is malformed", 422)
    port = parts.port or (443 if parts.scheme == "https" else 80)

    request_headers = dict(spec.headers)
    body_bytes = spec.body.encode("utf-8") if spec.body is not None else b""
    if len(body_bytes) > 65536:
        raise ControlPlaneError("HTTP body exceeds 65536 UTF-8 bytes", 422)

    resolved_addresses: list[str] = []
    if transport is None:
        resolved_addresses = resolve_host(host, port, allow_loopback)

    execution = HttpExecution(
        project_id=task.project_id,
        task_id=task.id,
        method=spec.method,
        url=spec.url,
        request_headers=_redact_headers(request_headers),
        request_body_sha256=hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
        request_bytes=len(body_bytes),
        response_headers={},
        resolved_addresses=resolved_addresses,
        redirect_count=0,
        outcome="pending",
    )
    session.add(execution)
    session.flush()

    try:
        timeout = httpx.Timeout(spec.timeout_ms / 1000)
        client_kwargs: dict[str, object] = {"timeout": timeout, "follow_redirects": False}
        if transport is not None:
            client_kwargs["transport"] = transport
        with httpx.Client(**client_kwargs) as client:
            response = client.request(
                spec.method,
                spec.url,
                headers=request_headers,
                content=body_bytes,
            )
            location = response.headers.get("location")
            if 300 <= response.status_code < 400:
                execution.redirect_count = 1
                execution.outcome = "redirect_blocked"
                execution.status_code = response.status_code
                execution.response_headers = _redact_headers(dict(response.headers))
                execution.error = "redirect was not followed; Location=" + (location or "[missing]")
                execution.response_bytes = 0
                session.commit()
                _audit(session, project_id=task.project_id, actor_id=operator_id, action="http.request", outcome="denied", entity_type="http_execution", entity_id=execution.id, details={"reason": "redirect_blocked", "method": spec.method})
                session.commit()
                return execution

            collected = bytearray()
            for chunk in response.iter_bytes(chunk_size=8192):
                if len(collected) + len(chunk) > spec.max_response_bytes:
                    collected.extend(chunk[: max(0, spec.max_response_bytes - len(collected))])
                    execution.outcome = "response_truncated"
                    execution.error = f"response exceeded max_response_bytes={spec.max_response_bytes}"
                    break
                collected.extend(chunk)

            execution.status_code = response.status_code
            execution.response_headers = _redact_headers(dict(response.headers))
            execution.response_bytes = len(collected)
            execution.response_sha256 = hashlib.sha256(collected).hexdigest()
            if execution.outcome == "pending":
                execution.outcome = "completed"
        session.commit()
        _audit(session, project_id=task.project_id, actor_id=operator_id, action="http.request", outcome="allowed", entity_type="http_execution", entity_id=execution.id, details={"status_code": execution.status_code, "method": spec.method, "response_truncated": execution.outcome == "response_truncated"})
        session.commit()
        session.refresh(execution)
        return execution
    except (httpx.HTTPError, OSError) as exc:
        execution.outcome = "failed"
        execution.error = f"{type(exc).__name__}: {exc}"[:2000]
        session.commit()
        _audit(session, project_id=task.project_id, actor_id=operator_id, action="http.request", outcome="failed", entity_type="http_execution", entity_id=execution.id, details={"error_type": type(exc).__name__})
        session.commit()
        session.refresh(execution)
        return execution
