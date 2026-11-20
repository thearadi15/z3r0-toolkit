from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("budget_limit_units > 0", name="ck_projects_budget_positive"),
        CheckConstraint("budget_reserved_units >= 0", name="ck_projects_budget_reserved_nonnegative"),
        CheckConstraint("budget_reserved_units <= budget_limit_units", name="ck_projects_budget_within_limit"),
        CheckConstraint("iteration_limit > 0", name="ck_projects_iterations_positive"),
        CheckConstraint(
            "iterations_reserved >= 0 AND iterations_reserved <= iteration_limit",
            name="ck_projects_iterations_within_limit",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active")
    budget_limit_units: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_reserved_units: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    iteration_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    iterations_reserved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    scopes: Mapped[list["ScopeEntry"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="ScopeEntry.id"
    )
    tasks: Mapped[list["ResearchTask"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ScopeEntry(Base):
    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint("project_id", "host", "scheme", "port", name="uq_scopes_origin"),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_scopes_port_range"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    project: Mapped[Project] = relationship(back_populates="scopes")


class ResearchTask(Base):
    __tablename__ = "research_tasks"
    __table_args__ = (
        CheckConstraint("requested_budget_units > 0", name="ck_tasks_budget_positive"),
        CheckConstraint("requested_iterations > 0", name="ck_tasks_iterations_positive"),
        Index("ix_tasks_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    objective: Mapped[str] = mapped_column(String(2000), nullable=False)
    requested_budget_units: Mapped[int] = mapped_column(Integer, nullable=False)
    requested_iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="tasks")
    scope: Mapped[ScopeEntry] = relationship()
    approvals: Mapped[list["Approval"]] = relationship(
        back_populates="task", cascade="all, delete-orphan", order_by="Approval.created_at"
    )


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint("max_budget_units > 0", name="ck_approvals_budget_positive"),
        CheckConstraint("max_iterations > 0", name="ck_approvals_iterations_positive"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("research_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    max_budget_units: Mapped[int] = mapped_column(Integer, nullable=False)
    max_iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="approved")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    task: Mapped[ResearchTask] = relationship(back_populates="approvals")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_project_created", "project_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"
    __table_args__ = (
        UniqueConstraint("project_id", "payload_sha256", name="uq_evidence_project_payload"),
        Index("ix_evidence_project_imported", "project_id", "imported_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_sha256: Mapped[str | None] = mapped_column(String(64))
    source_tool: Mapped[str] = mapped_column(String(80), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(80))
    artifact_name: Mapped[str | None] = mapped_column(String(255))
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    run_status: Mapped[str] = mapped_column(String(16), nullable=False)
    coverage_note: Mapped[str | None] = mapped_column(Text)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    redacted_field_count: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_by: Mapped[str] = mapped_column(String(128), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    observations: Mapped[list["EvidenceObservation"]] = relationship(
        back_populates="artifact",
        cascade="all, delete-orphan",
        order_by="EvidenceObservation.ordinal",
    )


class EvidenceObservation(Base):
    __tablename__ = "evidence_observations"
    __table_args__ = (
        UniqueConstraint("artifact_id", "ordinal", name="uq_evidence_observation_ordinal"),
        Index("ix_evidence_observation_kind", "artifact_id", "kind"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_artifacts.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(String(2048), nullable=False)
    source_record_id: Mapped[str | None] = mapped_column(String(128))
    record_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    data: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    artifact: Mapped[EvidenceArtifact] = relationship(back_populates="observations")


class IntelligenceAsset(Base):
    __tablename__ = "intelligence_assets"
    __table_args__ = (
        UniqueConstraint("project_id", "host", "scheme", "port", name="uq_intelligence_asset_origin"),
        Index("ix_intelligence_assets_project_host", "project_id", "host"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    scheme: Mapped[str | None] = mapped_column(String(8))
    port: Mapped[int | None] = mapped_column(Integer)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    data: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class IntelligenceEndpoint(Base):
    __tablename__ = "intelligence_endpoints"
    __table_args__ = (
        UniqueConstraint("project_id", "host", "scheme", "port", "method", "path", name="uq_intelligence_endpoint_identity"),
        Index("ix_intelligence_endpoints_project_priority", "project_id", "priority_score"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str | None] = mapped_column(String(253))
    scheme: Mapped[str | None] = mapped_column(String(8))
    port: Mapped[int | None] = mapped_column(Integer)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter_shape: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    origin_declared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EndpointEvidence(Base):
    __tablename__ = "endpoint_evidence"

    endpoint_id: Mapped[str] = mapped_column(ForeignKey("intelligence_endpoints.id", ondelete="CASCADE"), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("evidence_observations.id", ondelete="CASCADE"), primary_key=True)
    relation: Mapped[str] = mapped_column(String(16), nullable=False, default="supporting")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AdvisoryCorrelation(Base):
    __tablename__ = "advisory_correlations"
    __table_args__ = (
        CheckConstraint("status IN ('candidate', 'needs_review', 'accepted', 'rejected')", name="ck_advisory_status"),
        Index("ix_advisories_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False)
    advisory_id: Mapped[str] = mapped_column(String(32), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_version: Mapped[str] = mapped_column(String(255), nullable=False)
    source_name: Mapped[str] = mapped_column(String(80), nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="candidate")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class SourceClaim(Base):
    __tablename__ = "source_claims"
    __table_args__ = (
        CheckConstraint("status IN ('candidate', 'needs_review', 'accepted', 'rejected')", name="ck_source_claim_status"),
        Index("ix_source_claims_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False)
    repository: Mapped[str] = mapped_column(String(2048), nullable=False)
    revision: Mapped[str] = mapped_column(String(128), nullable=False)
    claim_type: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(2048))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    statement: Mapped[str] = mapped_column(String(2000), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="candidate")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ReproductionRecord(Base):
    __tablename__ = "reproduction_records"
    __table_args__ = (
        CheckConstraint("outcome IN ('pending', 'succeeded', 'failed', 'blocked')", name="ck_reproduction_outcome"),
        Index("ix_reproduction_investigation", "investigation_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("finding_candidates.id", ondelete="SET NULL"))
    isolation: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    limits: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class SafePocTemplate(Base):
    __tablename__ = "safe_poc_templates"
    __table_args__ = (
        CheckConstraint("status IN ('draft', 'reviewed', 'rejected')", name="ck_poc_status"),
        Index("ix_pocs_finding_status", "finding_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding_candidates.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    approved_target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ResearchReport(Base):
    __tablename__ = "research_reports"
    __table_args__ = (
        CheckConstraint("status IN ('draft', 'reviewed', 'published')", name="ck_report_status"),
        Index("ix_reports_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    limitations: Mapped[str] = mapped_column(Text, nullable=False)
    findings_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ResearchProfile(Base):
    __tablename__ = "research_profiles"
    __table_args__ = (
        CheckConstraint("cpu_limit_percent >= 1 AND cpu_limit_percent <= 100", name="ck_profile_cpu"),
        CheckConstraint("memory_limit_mb >= 16 AND memory_limit_mb <= 65536", name="ck_profile_memory"),
        CheckConstraint("wall_time_seconds >= 1 AND wall_time_seconds <= 86400", name="ck_profile_time"),
        Index("ix_profiles_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cpu_limit_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    memory_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    wall_time_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    process_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="inactive")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class FindingCandidate(Base):
    __tablename__ = "finding_candidates"
    __table_args__ = (
        CheckConstraint("status IN ('candidate', 'needs_validation', 'validated', 'rejected')", name="ck_finding_status"),
        Index("ix_findings_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False)
    hypothesis_id: Mapped[str | None] = mapped_column(String(36))
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    statement: Mapped[str] = mapped_column(String(2000), nullable=False)
    impact: Mapped[str] = mapped_column(String(2000), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="candidate")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (
        CheckConstraint("relation IN ('originating', 'supporting', 'contradicting', 'independent')", name="ck_finding_evidence_relation"),
    )

    finding_id: Mapped[str] = mapped_column(ForeignKey("finding_candidates.id", ondelete="CASCADE"), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("evidence_observations.id", ondelete="CASCADE"), primary_key=True)
    relation: Mapped[str] = mapped_column(String(16), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class IndependentValidation(Base):
    __tablename__ = "independent_validations"
    __table_args__ = (
        CheckConstraint("verdict IN ('confirmed', 'rejected', 'inconclusive')", name="ck_validation_verdict"),
        Index("ix_validations_finding", "finding_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding_candidates.id", ondelete="CASCADE"), nullable=False)
    validator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    reproducible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ValidationEvidence(Base):
    __tablename__ = "validation_evidence"

    validation_id: Mapped[str] = mapped_column(ForeignKey("independent_validations.id", ondelete="CASCADE"), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("evidence_observations.id", ondelete="CASCADE"), primary_key=True)
    relation: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class BrowserExecution(Base):
    __tablename__ = "browser_executions"
    __table_args__ = (
        CheckConstraint("action_count >= 1 AND action_count <= 10", name="ck_browser_action_count_limit"),
        Index("ix_browser_executions_task_created", "task_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[str] = mapped_column(ForeignKey("research_tasks.id", ondelete="CASCADE"), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    action_count: Mapped[int] = mapped_column(Integer, nullable=False)
    actions: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    blocked_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    final_url: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class HttpExecution(Base):
    __tablename__ = "http_executions"
    __table_args__ = (
        CheckConstraint("request_bytes <= 65536", name="ck_http_request_bytes_limit"),
        CheckConstraint("response_bytes <= 1048576", name="ck_http_response_bytes_limit"),
        Index("ix_http_executions_task_created", "task_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    task_id: Mapped[str] = mapped_column(ForeignKey("research_tasks.id", ondelete="CASCADE"), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    request_headers: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    request_body_sha256: Mapped[str | None] = mapped_column(String(64))
    request_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    response_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_addresses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    redirect_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ResearchInvestigation(Base):
    __tablename__ = "research_investigations"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_investigation_task"),
        CheckConstraint("budget_limit_units > 0", name="ck_investigation_budget_positive"),
        CheckConstraint(
            "budget_used_units >= 0 AND budget_used_units <= budget_limit_units",
            name="ck_investigation_budget_within_limit",
        ),
        CheckConstraint("iteration_limit > 0", name="ck_investigation_iterations_positive"),
        CheckConstraint(
            "iterations_used >= 0 AND iterations_used <= iteration_limit",
            name="ck_investigation_iterations_within_limit",
        ),
        Index("ix_investigations_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("research_tasks.id", ondelete="CASCADE"), nullable=False
    )
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    objective: Mapped[str] = mapped_column(String(2000), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active")
    budget_limit_units: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_used_units: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    iteration_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    iterations_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    project: Mapped[Project] = relationship()
    task: Mapped[ResearchTask] = relationship()
    scope: Mapped[ScopeEntry] = relationship()
    hypotheses: Mapped[list["ResearchHypothesis"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", order_by="ResearchHypothesis.created_at"
    )
    proposals: Mapped[list["ResearchProposal"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", order_by="ResearchProposal.created_at"
    )


class ResearchHypothesis(Base):
    __tablename__ = "research_hypotheses"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_hypothesis_confidence_range"),
        Index("ix_hypotheses_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    statement: Mapped[str] = mapped_column(String(2000), nullable=False)
    expected_vulnerable_behavior: Mapped[str] = mapped_column(String(2000), nullable=False)
    expected_secure_behavior: Mapped[str] = mapped_column(String(2000), nullable=False)
    potential_impact: Mapped[str] = mapped_column(String(2000), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="proposed")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    investigation: Mapped[ResearchInvestigation] = relationship(back_populates="hypotheses")
    evidence_links: Mapped[list["HypothesisEvidence"]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan", order_by="HypothesisEvidence.created_at"
    )


class HypothesisEvidence(Base):
    __tablename__ = "hypothesis_evidence"
    __table_args__ = (
        CheckConstraint(
            "relation IN ('supporting', 'contradicting')", name="ck_hypothesis_evidence_relation"
        ),
        Index("ix_hypothesis_evidence_observation", "observation_id"),
    )

    hypothesis_id: Mapped[str] = mapped_column(
        ForeignKey("research_hypotheses.id", ondelete="CASCADE"), primary_key=True
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_observations.id", ondelete="CASCADE"), primary_key=True
    )
    relation: Mapped[str] = mapped_column(String(16), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    hypothesis: Mapped[ResearchHypothesis] = relationship(back_populates="evidence_links")
    observation: Mapped[EvidenceObservation] = relationship()


class ResearchProposal(Base):
    __tablename__ = "research_proposals"
    __table_args__ = (
        CheckConstraint("budget_units > 0", name="ck_proposal_budget_positive"),
        CheckConstraint("iteration_units > 0", name="ck_proposal_iterations_positive"),
        Index("ix_proposals_investigation_status", "investigation_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("research_investigations.id", ondelete="CASCADE"), nullable=False
    )
    hypothesis_id: Mapped[str] = mapped_column(
        ForeignKey("research_hypotheses.id", ondelete="CASCADE"), nullable=False
    )
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(String(2000), nullable=False)
    budget_units: Mapped[int] = mapped_column(Integer, nullable=False)
    iteration_units: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending_review")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    investigation: Mapped[ResearchInvestigation] = relationship(back_populates="proposals")
    hypothesis: Mapped[ResearchHypothesis] = relationship()
    scope: Mapped[ScopeEntry] = relationship()
    evidence_links: Mapped[list["ProposalEvidence"]] = relationship(
        back_populates="proposal", cascade="all, delete-orphan", order_by="ProposalEvidence.created_at"
    )


class ProposalEvidence(Base):
    __tablename__ = "proposal_evidence"
    __table_args__ = (Index("ix_proposal_evidence_observation", "observation_id"),)

    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("research_proposals.id", ondelete="CASCADE"), primary_key=True
    )
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_observations.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    proposal: Mapped[ResearchProposal] = relationship(back_populates="evidence_links")
    observation: Mapped[EvidenceObservation] = relationship()
