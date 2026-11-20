from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import Approval, AuditEvent, Project, ResearchTask, ScopeEntry, utc_now
from z3r0_platform.schemas import (
    APPROVAL_REQUIRED_ACTIONS,
    ActionKind,
    ApprovalCreate,
    ProjectCreate,
    TaskCreate,
    normalize_target_url,
)


class _AuthorizationFailed(Exception):
    pass


class ControlPlaneError(Exception):
    def __init__(self, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def _is_scope_match(scope: ScopeEntry, host: str, scheme: str, port: int) -> bool:
    if scope.scheme != scheme or scope.port != port:
        return False
    if scope.host == host:
        return True
    if not scope.include_subdomains or ":" in scope.host:
        return False
    try:
        from ipaddress import ip_address

        ip_address(scope.host)
        return False
    except ValueError:
        return host.endswith(f".{scope.host}")


def _find_scope(
    scopes: list[ScopeEntry], target_url: str, *, at: datetime | None = None
) -> ScopeEntry | None:
    _, host, scheme, port = normalize_target_url(target_url)
    now = at or datetime.now(timezone.utc)
    for scope in scopes:
        expiry = scope.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            continue
        if _is_scope_match(scope, host, scheme, port):
            return scope
    return None


def _audit(
    session: Session,
    *,
    project_id: str,
    actor_id: str,
    action: str,
    outcome: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, object] | None = None,
) -> None:
    session.add(
        AuditEvent(
            project_id=project_id,
            actor_id=actor_id,
            action=action,
            outcome=outcome,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details or {},
        )
    )


def create_project(session: Session, operator_id: str, spec: ProjectCreate) -> Project:
    project = Project(
        owner_id=operator_id,
        name=spec.name,
        budget_limit_units=spec.budget_limit_units,
        iteration_limit=spec.iteration_limit,
    )
    session.add(project)
    session.flush()
    for scope_spec in spec.scopes:
        session.add(
            ScopeEntry(
                project_id=project.id,
                host=scope_spec.host,
                scheme=scope_spec.scheme,
                port=scope_spec.port,
                include_subdomains=scope_spec.include_subdomains,
                expires_at=scope_spec.expires_at,
            )
        )
    _audit(
        session,
        project_id=project.id,
        actor_id=operator_id,
        action="project.created",
        outcome="allowed",
        entity_type="project",
        entity_id=project.id,
        details={"scope_count": len(spec.scopes)},
    )
    session.commit()
    return session.scalar(
        select(Project).where(Project.id == project.id).options(selectinload(Project.scopes))
    )


def get_owned_project(session: Session, project_id: str, operator_id: str) -> Project:
    project = session.scalar(
        select(Project)
        .where(Project.id == project_id, Project.owner_id == operator_id)
        .options(selectinload(Project.scopes))
    )
    if project is None:
        raise ControlPlaneError("project not found", 404)
    return project


def propose_task(
    session: Session, project_id: str, operator_id: str, spec: TaskCreate
) -> ResearchTask:
    project = get_owned_project(session, project_id, operator_id)
    if project.status != "active":
        raise ControlPlaneError("project is not active", 409)
    scope = _find_scope(project.scopes, spec.target_url)
    if scope is None:
        _audit(
            session,
            project_id=project.id,
            actor_id=operator_id,
            action="task.proposed",
            outcome="denied",
            entity_type="project",
            entity_id=project.id,
            details={"reason": "target_out_of_scope", "action": spec.action.value},
        )
        session.commit()
        raise ControlPlaneError("target is outside active project scope", 403)

    task = ResearchTask(
        project_id=project.id,
        scope_id=scope.id,
        action=spec.action.value,
        target_url=spec.target_url,
        objective=spec.objective,
        requested_budget_units=spec.requested_budget_units,
        requested_iterations=spec.requested_iterations,
        status="proposed",
    )
    session.add(task)
    session.flush()
    _audit(
        session,
        project_id=project.id,
        actor_id=operator_id,
        action="task.proposed",
        outcome="allowed",
        entity_type="task",
        entity_id=task.id,
        details={"action": task.action, "scope_id": scope.id},
    )
    session.commit()
    return session.get(ResearchTask, task.id)


def grant_approval(
    session: Session, task_id: str, operator_id: str, spec: ApprovalCreate
) -> Approval:
    task = session.scalar(
        select(ResearchTask)
        .join(Project)
        .where(ResearchTask.id == task_id, Project.owner_id == operator_id)
        .options(selectinload(ResearchTask.project), selectinload(ResearchTask.scope))
    )
    if task is None:
        raise ControlPlaneError("task not found", 404)
    if task.status != "proposed":
        raise ControlPlaneError("only proposed tasks can be approved", 409)
    if ActionKind(task.action) not in APPROVAL_REQUIRED_ACTIONS:
        raise ControlPlaneError("this task action does not require an active-test approval", 409)
    if spec.max_budget_units > task.requested_budget_units:
        raise ControlPlaneError("approval budget cannot exceed the task request", 422)
    if spec.max_iterations > task.requested_iterations:
        raise ControlPlaneError("approval iterations cannot exceed the task request", 422)
    if _find_scope(task.project.scopes, task.target_url) is None:
        raise ControlPlaneError("task target is outside active project scope", 403)

    approval = Approval(
        task_id=task.id,
        approver_id=operator_id,
        target_url=task.target_url,
        max_budget_units=spec.max_budget_units,
        max_iterations=spec.max_iterations,
        expires_at=spec.expires_at,
    )
    session.add(approval)
    session.flush()
    _audit(
        session,
        project_id=task.project_id,
        actor_id=operator_id,
        action="task.approved",
        outcome="allowed",
        entity_type="approval",
        entity_id=approval.id,
        details={
            "task_id": task.id,
            "max_budget_units": approval.max_budget_units,
            "max_iterations": approval.max_iterations,
        },
    )
    session.commit()
    return session.get(Approval, approval.id)


def revoke_approval(session: Session, approval_id: str, operator_id: str) -> Approval:
    approval = session.scalar(
        select(Approval)
        .join(ResearchTask)
        .join(Project)
        .where(Approval.id == approval_id, Project.owner_id == operator_id)
        .options(selectinload(Approval.task).selectinload(ResearchTask.project))
    )
    if approval is None:
        raise ControlPlaneError("approval not found", 404)
    if approval.status != "approved":
        raise ControlPlaneError("approval is not active", 409)
    if approval.task.status != "proposed":
        raise ControlPlaneError("approval cannot be revoked after task authorization", 409)

    approval.status = "revoked"
    _audit(
        session,
        project_id=approval.task.project_id,
        actor_id=operator_id,
        action="approval.revoked",
        outcome="allowed",
        entity_type="approval",
        entity_id=approval.id,
        details={"task_id": approval.task_id},
    )
    session.commit()
    session.refresh(approval)
    return approval


def authorize_task(session: Session, task_id: str, operator_id: str) -> ResearchTask:
    task = session.scalar(
        select(ResearchTask)
        .join(Project)
        .where(ResearchTask.id == task_id, Project.owner_id == operator_id)
        .options(
            selectinload(ResearchTask.project).selectinload(Project.scopes),
            selectinload(ResearchTask.approvals),
        )
    )
    if task is None:
        raise ControlPlaneError("task not found", 404)
    denial: str | None = None
    now = utc_now()

    if task.status != "proposed":
        denial = "task is not in the proposed state"
    elif task.project.status != "active":
        denial = "project is not active"
    elif _find_scope(task.project.scopes, task.target_url, at=now) is None:
        denial = "task target is outside active project scope"
    elif ActionKind(task.action) in APPROVAL_REQUIRED_ACTIONS and not _has_valid_approval(task, now):
        denial = "valid task-specific human approval is required"

    if denial is None:
        try:
            with session.begin_nested():
                reservation = session.execute(
                    update(Project)
                    .where(
                        Project.id == task.project_id,
                        Project.owner_id == operator_id,
                        Project.status == "active",
                        Project.budget_reserved_units + task.requested_budget_units
                        <= Project.budget_limit_units,
                        Project.iterations_reserved + task.requested_iterations
                        <= Project.iteration_limit,
                    )
                    .values(
                        budget_reserved_units=Project.budget_reserved_units
                        + task.requested_budget_units,
                        iterations_reserved=Project.iterations_reserved
                        + task.requested_iterations,
                    )
                )
                if reservation.rowcount != 1:
                    raise _AuthorizationFailed(
                        "project budget or iteration limit would be exceeded"
                    )
                claim = session.execute(
                    update(ResearchTask)
                    .where(ResearchTask.id == task.id, ResearchTask.status == "proposed")
                    .values(status="authorized", authorized_at=now)
                )
                if claim.rowcount != 1:
                    raise _AuthorizationFailed("task was already authorized or changed")
        except _AuthorizationFailed as error:
            denial = str(error)

    if denial is not None:
        _audit(
            session,
            project_id=task.project_id,
            actor_id=operator_id,
            action="task.authorized",
            outcome="denied",
            entity_type="task",
            entity_id=task.id,
            details={"reason": denial},
        )
        session.commit()
        raise ControlPlaneError(denial, 409)

    task.status = "authorized"
    task.authorized_at = now
    _audit(
        session,
        project_id=task.project_id,
        actor_id=operator_id,
        action="task.authorized",
        outcome="allowed",
        entity_type="task",
        entity_id=task.id,
        details={
            "budget_reserved_units": task.requested_budget_units,
            "iterations_reserved": task.requested_iterations,
            "execution_started": False,
        },
    )
    session.commit()
    session.refresh(task)
    return task


def _has_valid_approval(task: ResearchTask, now: datetime) -> bool:
    for approval in task.approvals:
        expires_at = approval.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if (
            approval.status == "approved"
            and approval.target_url == task.target_url
            and approval.max_budget_units >= task.requested_budget_units
            and approval.max_iterations >= task.requested_iterations
            and expires_at > now
        ):
            return True
    return False


def approve_task_input(
    max_budget_units: int, max_iterations: int, expires_at: datetime
) -> ApprovalCreate:
    return ApprovalCreate(
        max_budget_units=max_budget_units,
        max_iterations=max_iterations,
        expires_at=expires_at,
    )
