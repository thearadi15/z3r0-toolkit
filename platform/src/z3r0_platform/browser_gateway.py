import ipaddress
import os
import socket
import time
from urllib.parse import urlsplit

from sqlalchemy import select, func
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import BrowserExecution, Project, ResearchTask, utc_now
from z3r0_platform.policy import ControlPlaneError, _audit, _find_scope, _has_valid_approval
from z3r0_platform.schemas import BrowserScenarioCreate


def _usable_address(host: str, allow_loopback: bool) -> bool:
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for family, _, _, _, sockaddr in records:
        address = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        blocked = parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified
        if blocked and not (allow_loopback and parsed.is_loopback):
            return False
        if not blocked or (allow_loopback and parsed.is_loopback):
            return True
    return False


class PlaywrightBrowserDriver:
    def execute(self, actions, scopes, allow_loopback: bool) -> dict[str, object]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ControlPlaneError("Playwright is not installed; use a provided browser driver or install browser dependencies", 503) from exc

        blocked = 0
        final_url = None
        action_results: list[dict[str, object]] = []
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except Exception as exc:
                raise ControlPlaneError("Playwright Chromium is unavailable; run playwright install chromium", 503) from exc
            context = browser.new_context()
            page = context.new_page()

            def route_handler(route):
                nonlocal blocked
                url = route.request.url
                if url.startswith(("http://", "https://")):
                    try:
                        normalized, host, scheme, port = __import__("z3r0_platform.schemas", fromlist=["normalize_target_url"]).normalize_target_url(url)
                        allowed = _find_scope(scopes, normalized)
                        allowed_address = _usable_address(host, allow_loopback)
                        if allowed is None or not allowed_address:
                            blocked += 1
                            route.abort()
                            return
                    except ValueError:
                        blocked += 1
                        route.abort()
                        return
                route.continue_()

            page.route("**/*", route_handler)
            try:
                for ordinal, action in enumerate(actions):
                    kind = action.action
                    try:
                        if kind == "navigate":
                            response = page.goto(action.url, wait_until="domcontentloaded", timeout=action.timeout_ms)
                            final_url = page.url
                            action_results.append({"ordinal": ordinal, "action": kind, "outcome": "completed", "detail": f"status={response.status if response else 'none'}"})
                        elif kind == "click":
                            page.locator(action.selector).click(timeout=action.timeout_ms)
                            action_results.append({"ordinal": ordinal, "action": kind, "outcome": "completed"})
                        elif kind == "type":
                            value = os.getenv(action.text_ref)
                            if value is None:
                                raise ControlPlaneError(f"browser text reference {action.text_ref} is not configured", 400)
                            page.locator(action.selector).fill(value, timeout=action.timeout_ms)
                            action_results.append({"ordinal": ordinal, "action": kind, "outcome": "completed", "detail": "text_ref_used"})
                        elif kind == "wait":
                            time.sleep(action.timeout_ms / 1000)
                            action_results.append({"ordinal": ordinal, "action": kind, "outcome": "completed"})
                    except Exception as exc:
                        action_results.append({"ordinal": ordinal, "action": kind, "outcome": "failed", "detail": type(exc).__name__})
                        break
            finally:
                context.close()
                browser.close()
        outcome = "completed" if action_results and all(item["outcome"] == "completed" for item in action_results) and len(action_results) == len(actions) else "partial"
        return {"outcome": outcome, "actions": action_results, "blocked_requests": blocked, "final_url": final_url}


def execute_authorized_browser_scenario(
    session: Session,
    task_id: str,
    operator_id: str,
    spec: BrowserScenarioCreate,
    *,
    allow_loopback: bool = False,
    browser_driver=None,
) -> BrowserExecution:
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
    if task.action != "browser_action":
        raise ControlPlaneError("task action does not permit browser execution", 409)

    now = utc_now()
    if task.project.status != "active":
        raise ControlPlaneError("project is not active", 409)
    if not _has_valid_approval(task, now):
        raise ControlPlaneError("valid task-specific human approval is required", 409)

    for action in spec.actions:
        if action.action == "navigate":
            if _find_scope(task.project.scopes, action.url, at=now) is None:
                raise ControlPlaneError("browser navigation URL is outside active project scope", 403)

    completed = session.scalar(select(func.count(BrowserExecution.id)).where(BrowserExecution.task_id == task.id)) or 0
    if completed + 1 > task.requested_iterations:
        raise ControlPlaneError("task iteration limit would be exceeded", 409)
    if completed + 1 > task.requested_budget_units:
        raise ControlPlaneError("task budget limit would be exceeded", 409)

    execution = BrowserExecution(
        project_id=task.project_id,
        task_id=task.id,
        outcome="pending",
        action_count=len(spec.actions),
        actions=[],
        blocked_requests=0,
    )
    session.add(execution)
    session.flush()

    driver = browser_driver or PlaywrightBrowserDriver()
    try:
        result = driver.execute(spec.actions, task.project.scopes, allow_loopback)
    except ControlPlaneError as exc:
        execution.outcome = "failed"
        execution.error = exc.detail
        execution.actions = []
        session.commit()
        _audit(session, project_id=task.project_id, actor_id=operator_id, action="browser.scenario", outcome="failed", entity_type="browser_execution", entity_id=execution.id, details={"reason": exc.detail})
        session.commit()
        return execution

    execution.outcome = str(result["outcome"])
    execution.actions = result["actions"]
    execution.blocked_requests = int(result["blocked_requests"])
    execution.final_url = result["final_url"]
    session.commit()
    _audit(session, project_id=task.project_id, actor_id=operator_id, action="browser.scenario", outcome="allowed", entity_type="browser_execution", entity_id=execution.id, details={"action_count": len(spec.actions), "blocked_requests": execution.blocked_requests, "outcome": execution.outcome})
    session.commit()
    session.refresh(execution)
    return execution
