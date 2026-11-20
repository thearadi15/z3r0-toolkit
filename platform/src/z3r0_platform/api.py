from collections.abc import Generator
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from z3r0_platform.config import Settings
from z3r0_platform.database import make_engine, make_session_factory
from z3r0_platform.evidence import get_owned_evidence, import_evidence, list_owned_evidence
from z3r0_platform.evidence_importers import parse_evidence_source
from z3r0_platform.intelligence import list_intelligence_assets, list_intelligence_endpoints, rebuild_intelligence
from z3r0_platform.http_gateway import execute_authorized_http_request
from z3r0_platform.browser_gateway import execute_authorized_browser_scenario
from z3r0_platform.validation import add_independent_validation, create_finding, review_finding
from z3r0_platform.research_extensions import create_advisory, create_report, create_reproduction_record, create_research_profile, create_safe_poc, create_source_claim
from z3r0_platform.models import AuditEvent, EvidenceArtifact, Project, ResearchTask
from z3r0_platform.policy import (
    ControlPlaneError,
    authorize_task,
    create_project,
    get_owned_project,
    grant_approval,
    propose_task,
    revoke_approval,
    _find_scope,
)
from z3r0_platform.supervisor import (
    change_hypothesis_status,
    change_investigation_status,
    create_hypothesis,
    create_investigation,
    create_proposal,
    get_owned_investigation,
    review_proposal,
)
from z3r0_platform.schemas import (
    ApprovalCreate,
    BrowserScenarioCreate,
    AdvisoryCorrelationCreate,
    FindingCreate,
    FindingReview,
    IndependentValidationCreate,
    ReportCreate,
    ReproductionRecordCreate,
    ResearchProfileCreate,
    SafePocCreate,
    SourceClaimCreate,
    HttpRequestCreate,
    HypothesisCreate,
    HypothesisStatusChange,
    InvestigationStateChange,
    EvidenceArtifactDetailResponse,
    EvidenceArtifactResponse,
    EvidenceImport,
    EvidenceImportResponse,
    EvidenceSourceImport,
    HypothesisResponse,
    InvestigationResponse,
    ProjectCreate,
    ProjectResponse,
    ProposalCreate,
    ProposalReview,
    ProposalResponse,
    TaskCreate,
    TaskResponse,
)


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    resolved_engine = engine or make_engine(resolved_settings.database_url)
    session_factory = make_session_factory(resolved_engine)
    app = FastAPI(
        title="z3r0 Security Research Control Plane",
        version="0.1.0",
        description="Human-governed project scope, task approval, and budget control.",
    )
    app.state.engine = resolved_engine
    app.state.session_factory = session_factory
    app.state.allow_loopback = resolved_settings.allow_loopback
    app.state.http_transport = None
    app.state.browser_driver = None

    def get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    def require_operator(x_api_token: str | None = Header(default=None)) -> str:
        expected = resolved_settings.api_token
        if not expected:
            raise HTTPException(
                status_code=503, detail="control-plane API is disabled until Z3R0_API_TOKEN is set"
            )
        if x_api_token is None or not secrets.compare_digest(x_api_token, expected):
            raise HTTPException(status_code=401, detail="invalid API token")
        return resolved_settings.operator_id

    def translate_error(error: ControlPlaneError) -> HTTPException:
        return HTTPException(status_code=error.status_code, detail=error.detail)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
    def create_project_route(
        spec: ProjectCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> Project:
        try:
            return create_project(session, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.get("/projects/{project_id}", response_model=ProjectResponse)
    def get_project_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> Project:
        try:
            return get_owned_project(session, project_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.post(
        "/projects/{project_id}/tasks",
        response_model=TaskResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def propose_task_route(
        project_id: str,
        spec: TaskCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> ResearchTask:
        try:
            return propose_task(session, project_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.post("/tasks/{task_id}/approvals", status_code=status.HTTP_201_CREATED)
    def grant_approval_route(
        task_id: str,
        spec: ApprovalCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            approval = grant_approval(session, task_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "id": approval.id,
            "task_id": approval.task_id,
            "approver_id": approval.approver_id,
            "max_budget_units": approval.max_budget_units,
            "max_iterations": approval.max_iterations,
            "expires_at": approval.expires_at,
            "status": approval.status,
        }

    @app.post("/tasks/{task_id}/authorize", response_model=TaskResponse)
    def authorize_task_route(
        task_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> ResearchTask:
        try:
            return authorize_task(session, task_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.post("/approvals/{approval_id}/revoke")
    def revoke_approval_route(
        approval_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            approval = revoke_approval(session, approval_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "id": approval.id,
            "task_id": approval.task_id,
            "status": approval.status,
        }

    @app.get("/projects/{project_id}/audit")
    def list_audit_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
        limit: int = 100,
    ) -> list[dict[str, object]]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        try:
            project = get_owned_project(session, project_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.project_id == project.id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id)
            .limit(limit)
        )
        return [
            {
                "id": event.id,
                "actor_id": event.actor_id,
                "action": event.action,
                "outcome": event.outcome,
                "entity_type": event.entity_type,
                "entity_id": event.entity_id,
                "details": event.details,
                "created_at": event.created_at,
            }
            for event in events
        ]

    @app.post("/projects/{project_id}/intelligence/rebuild")
    def rebuild_intelligence_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, int]:
        try:
            return rebuild_intelligence(session, project_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.get("/projects/{project_id}/intelligence/assets")
    def list_intelligence_assets_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
        limit: int = 100,
    ) -> list[dict[str, object]]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        try:
            assets = list_intelligence_assets(session, project_id, operator_id, limit)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return [{"id": item.id, "host": item.host, "scheme": item.scheme, "port": item.port, "evidence_count": item.evidence_count, "priority_score": item.priority_score, "data": item.data, "updated_at": item.updated_at} for item in assets]

    @app.get("/projects/{project_id}/intelligence/endpoints")
    def list_intelligence_endpoints_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
        limit: int = 100,
    ) -> list[dict[str, object]]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        try:
            endpoints = list_intelligence_endpoints(session, project_id, operator_id, limit)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return [{"id": item.id, "host": item.host, "scheme": item.scheme, "port": item.port, "method": item.method, "path": item.path, "parameter_shape": item.parameter_shape, "evidence_count": item.evidence_count, "priority_score": item.priority_score, "origin_declared": item.origin_declared, "updated_at": item.updated_at} for item in endpoints]

    @app.post("/tasks/{task_id}/http-execute")
    def execute_http_route(
        task_id: str,
        spec: HttpRequestCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            execution = execute_authorized_http_request(
                session,
                task_id,
                operator_id,
                spec,
                allow_loopback=bool(app.state.allow_loopback),
                transport=getattr(app.state, "http_transport", None),
            )
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "id": execution.id,
            "task_id": execution.task_id,
            "method": execution.method,
            "url": execution.url,
            "status_code": execution.status_code,
            "outcome": execution.outcome,
            "redirect_count": execution.redirect_count,
            "resolved_addresses": execution.resolved_addresses,
            "request_bytes": execution.request_bytes,
            "response_bytes": execution.response_bytes,
            "response_sha256": execution.response_sha256,
            "error": execution.error,
            "created_at": execution.created_at,
        }

    @app.post("/tasks/{task_id}/curl-export")
    def export_curl_route(
        task_id: str,
        spec: HttpRequestCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, str]:
        task = session.scalar(
            select(ResearchTask)
            .join(Project)
            .where(ResearchTask.id == task_id, Project.owner_id == operator_id)
        )
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        if task.status != "authorized":
            raise HTTPException(status_code=409, detail="task is not authorized")
        if task.action != "http_request":
            raise HTTPException(status_code=409, detail="task action does not permit HTTP export")
        if _find_scope(task.project.scopes, spec.url) is None:
            raise HTTPException(status_code=403, detail="target URL is outside active project scope")

        import shlex
        command = ["curl", "--request", spec.method, "--url", spec.url]
        for name, value in spec.headers.items():
            command.extend(["--header", f"{name}: {value}"])
        if spec.body is not None:
            command.extend(["--data-binary", spec.body])
        command.extend(["--max-time", str(max(1, spec.timeout_ms // 1000))])
        command.append("--max-redirs 0")
        return {"command": " ".join(shlex.quote(part) for part in command[:-1]) + " --max-redirs 0"}

    @app.post("/tasks/{task_id}/browser-execute")
    def execute_browser_route(
        task_id: str,
        spec: BrowserScenarioCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            execution = execute_authorized_browser_scenario(
                session,
                task_id,
                operator_id,
                spec,
                allow_loopback=bool(app.state.allow_loopback),
                browser_driver=getattr(app.state, "browser_driver", None),
            )
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "id": execution.id,
            "task_id": execution.task_id,
            "outcome": execution.outcome,
            "actions": execution.actions,
            "blocked_requests": execution.blocked_requests,
            "final_url": execution.final_url,
            "error": execution.error,
            "created_at": execution.created_at,
        }

    @app.post("/investigations/{investigation_id}/findings", status_code=status.HTTP_201_CREATED)
    def create_finding_route(
        investigation_id: str,
        spec: FindingCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            finding = create_finding(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": finding.id, "title": finding.title, "severity": finding.severity, "status": finding.status}

    @app.post("/investigations/{investigation_id}/advisories", status_code=status.HTTP_201_CREATED)
    def create_advisory_route(investigation_id: str, spec: AdvisoryCorrelationCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_advisory(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "advisory_id": row.advisory_id, "status": row.status}

    @app.post("/investigations/{investigation_id}/source-claims", status_code=status.HTTP_201_CREATED)
    def create_source_claim_route(investigation_id: str, spec: SourceClaimCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_source_claim(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "claim_type": row.claim_type, "status": row.status}

    @app.post("/findings/{finding_id}/pocs", status_code=status.HTTP_201_CREATED)
    def create_poc_route(finding_id: str, spec: SafePocCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_safe_poc(session, finding_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "format": row.format, "approved_target": row.approved_target, "status": row.status, "execution_enabled": False}

    @app.post("/investigations/{investigation_id}/reports", status_code=status.HTTP_201_CREATED)
    def create_report_route(investigation_id: str, spec: ReportCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_report(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "status": row.status, "finding_count": len(row.findings_json)}

    @app.post("/investigations/{investigation_id}/reproductions", status_code=status.HTTP_201_CREATED)
    def create_reproduction_route(investigation_id: str, spec: ReproductionRecordCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_reproduction_record(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "outcome": row.outcome, "isolation": row.isolation, "execution_performed": False}

    @app.post("/projects/{project_id}/research-profiles", status_code=status.HTTP_201_CREATED)
    def create_profile_route(project_id: str, spec: ResearchProfileCreate, operator_id: str = Depends(require_operator), session: Session = Depends(get_session)) -> dict[str, object]:
        try:
            row = create_research_profile(session, project_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": row.id, "status": row.status, "worker_enabled": False, "cpu_limit_percent": row.cpu_limit_percent, "memory_limit_mb": row.memory_limit_mb, "wall_time_seconds": row.wall_time_seconds}

    @app.post("/findings/{finding_id}/validations", status_code=status.HTTP_201_CREATED)
    def add_validation_route(
        finding_id: str,
        spec: IndependentValidationCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            validation = add_independent_validation(session, finding_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": validation.id, "verdict": validation.verdict, "reproducible": validation.reproducible}

    @app.post("/findings/{finding_id}/review")
    def review_finding_route(
        finding_id: str,
        spec: FindingReview,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            finding = review_finding(session, finding_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": finding.id, "status": finding.status, "reviewed_by": finding.reviewed_by}

    @app.post(
        "/projects/{project_id}/evidence",
        response_model=EvidenceImportResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def import_evidence_route(
        project_id: str,
        spec: EvidenceImport,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            artifact, duplicate = import_evidence(session, project_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "artifact": artifact,
            "observations": artifact.observations,
            "duplicate": duplicate,
        }

    @app.post(
        "/projects/{project_id}/evidence/import",
        response_model=EvidenceImportResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def import_evidence_source_route(
        project_id: str,
        source: EvidenceSourceImport,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            spec = parse_evidence_source(source)
            artifact, duplicate = import_evidence(session, project_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {
            "artifact": artifact,
            "observations": artifact.observations,
            "duplicate": duplicate,
        }

    @app.get(
        "/projects/{project_id}/evidence",
        response_model=list[EvidenceArtifactResponse],
    )
    def list_evidence_route(
        project_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
        limit: int = 100,
    ) -> list[EvidenceArtifact]:
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
        try:
            return list_owned_evidence(session, project_id, operator_id, limit)
        except ControlPlaneError as error:
            raise translate_error(error) from error

    @app.post("/tasks/{task_id}/investigations", status_code=status.HTTP_201_CREATED)
    def create_investigation_route(
        task_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            investigation = create_investigation(session, task_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": investigation.id, "task_id": investigation.task_id, "status": investigation.status, "budget_limit_units": investigation.budget_limit_units, "iteration_limit": investigation.iteration_limit}

    @app.get("/investigations/{investigation_id}")
    def get_investigation_route(
        investigation_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            investigation = get_owned_investigation(session, investigation_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": investigation.id, "project_id": investigation.project_id, "task_id": investigation.task_id, "target_url": investigation.target_url, "status": investigation.status, "budget_limit_units": investigation.budget_limit_units, "budget_used_units": investigation.budget_used_units, "iteration_limit": investigation.iteration_limit, "iterations_used": investigation.iterations_used}

    @app.post("/investigations/{investigation_id}/status")
    def change_investigation_status_route(
        investigation_id: str,
        spec: InvestigationStateChange,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            investigation = change_investigation_status(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": investigation.id, "status": investigation.status}

    @app.post("/investigations/{investigation_id}/hypotheses", status_code=status.HTTP_201_CREATED)
    def create_hypothesis_route(
        investigation_id: str,
        spec: HypothesisCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            hypothesis = create_hypothesis(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": hypothesis.id, "investigation_id": hypothesis.investigation_id, "category": hypothesis.category, "statement": hypothesis.statement, "confidence": hypothesis.confidence, "status": hypothesis.status}

    @app.post("/hypotheses/{hypothesis_id}/status")
    def change_hypothesis_status_route(
        hypothesis_id: str,
        spec: HypothesisStatusChange,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            hypothesis = change_hypothesis_status(session, hypothesis_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": hypothesis.id, "status": hypothesis.status}

    @app.post("/investigations/{investigation_id}/proposals", status_code=status.HTTP_201_CREATED)
    def create_proposal_route(
        investigation_id: str,
        spec: ProposalCreate,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            proposal = create_proposal(session, investigation_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": proposal.id, "investigation_id": proposal.investigation_id, "hypothesis_id": proposal.hypothesis_id, "action": proposal.action, "budget_units": proposal.budget_units, "iteration_units": proposal.iteration_units, "status": proposal.status}

    @app.post("/proposals/{proposal_id}/review")
    def review_proposal_route(
        proposal_id: str,
        spec: ProposalReview,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            proposal = review_proposal(session, proposal_id, operator_id, spec)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {"id": proposal.id, "status": proposal.status, "reviewed_by": proposal.reviewed_by}

    @app.get(
        "/evidence/{artifact_id}",
        response_model=EvidenceArtifactDetailResponse,
    )
    def get_evidence_route(
        artifact_id: str,
        operator_id: str = Depends(require_operator),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        try:
            artifact = get_owned_evidence(session, artifact_id, operator_id)
        except ControlPlaneError as error:
            raise translate_error(error) from error
        return {
            "artifact": artifact,
            "observations": artifact.observations,
        }

    return app


app = create_app()
