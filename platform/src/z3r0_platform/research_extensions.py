import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from z3r0_platform.models import (
    AdvisoryCorrelation,
    FindingCandidate,
    EvidenceArtifact,
    EvidenceObservation,
    Project,
    ReproductionRecord,
    ResearchProfile,
    ResearchReport,
    SafePocTemplate,
    SourceClaim,
    ResearchInvestigation,
    utc_now,
)
from z3r0_platform.policy import ControlPlaneError, _audit, _find_scope
from z3r0_platform.schemas import (
    AdvisoryCorrelationCreate,
    ReportCreate,
    ReproductionRecordCreate,
    ResearchProfileCreate,
    SafePocCreate,
    SourceClaimCreate,
)


def _owned_investigation(session: Session, investigation_id: str, operator_id: str) -> ResearchInvestigation:
    investigation = session.scalar(
        select(ResearchInvestigation)
        .join(Project)
        .where(ResearchInvestigation.id == investigation_id, Project.owner_id == operator_id)
    )
    if investigation is None:
        raise ControlPlaneError("investigation not found", 404)
    return investigation


def _owned_observation_ids(session: Session, operator_id: str, ids: list[str]) -> set[str]:
    requested = set(ids)
    if not requested:
        return set()
    observations = list(session.scalars(
        select(EvidenceObservation)
        .join(EvidenceArtifact, EvidenceArtifact.id == EvidenceObservation.artifact_id)
        .join(Project, Project.id == EvidenceArtifact.project_id)
        .where(EvidenceObservation.id.in_(requested), Project.owner_id == operator_id)
    ))
    return {observation.id for observation in observations}


def create_advisory(session: Session, investigation_id: str, operator_id: str, spec: AdvisoryCorrelationCreate) -> AdvisoryCorrelation:
    investigation = _owned_investigation(session, investigation_id, operator_id)
    evidence_ids = list(dict.fromkeys(spec.evidence_ids))
    if _owned_observation_ids(session, operator_id, evidence_ids) != set(evidence_ids):
        raise ControlPlaneError("advisory evidence contains missing or unowned observations", 404)
    row = AdvisoryCorrelation(
        investigation_id=investigation.id,
        advisory_id=spec.advisory_id,
        package_name=spec.package_name,
        affected_version=spec.affected_version,
        source_name=spec.source_name,
        retrieved_at=spec.retrieved_at,
        source_digest=spec.source_digest,
        status="candidate",
        created_by=operator_id,
        evidence_ids=evidence_ids,
    )
    session.add(row)
    session.flush()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="advisory.correlation_created", outcome="allowed", entity_type="advisory", entity_id=row.id, details={"advisory_id": row.advisory_id, "status": "candidate"})
    session.commit()
    session.refresh(row)
    return row


def create_source_claim(session: Session, investigation_id: str, operator_id: str, spec: SourceClaimCreate) -> SourceClaim:
    investigation = _owned_investigation(session, investigation_id, operator_id)
    row = SourceClaim(
        investigation_id=investigation.id,
        repository=spec.repository,
        revision=spec.revision,
        claim_type=spec.claim_type,
        file_path=spec.file_path,
        line_start=spec.line_start,
        line_end=spec.line_end,
        statement=spec.statement,
        evidence_digest=spec.evidence_digest,
        status="candidate",
        created_by=operator_id,
    )
    session.add(row)
    session.flush()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="source.claim_created", outcome="allowed", entity_type="source_claim", entity_id=row.id, details={"claim_type": row.claim_type, "status": "candidate"})
    session.commit()
    session.refresh(row)
    return row


def create_safe_poc(session: Session, finding_id: str, operator_id: str, spec: SafePocCreate) -> SafePocTemplate:
    finding = session.scalar(
        select(FindingCandidate)
        .join(ResearchInvestigation)
        .join(Project)
        .where(FindingCandidate.id == finding_id, Project.owner_id == operator_id)
    )
    if finding is None:
        raise ControlPlaneError("finding not found", 404)
    if finding.status != "validated":
        raise ControlPlaneError("PoC templates require a validated finding", 409)
    target = spec.approved_target
    from z3r0_platform.schemas import normalize_target_url
    try:
        normalized_target = normalize_target_url(target)[0]
    except ValueError as exc:
        raise ControlPlaneError(str(exc), 422) from exc
    investigation = session.get(ResearchInvestigation, finding.investigation_id)
    if _find_scope(investigation.project.scopes, normalized_target) is None:
        raise ControlPlaneError("approved PoC target is outside active project scope", 403)
    row = SafePocTemplate(
        finding_id=finding.id,
        title=spec.title,
        format=spec.format,
        content=spec.content,
        approved_target=normalized_target,
        status="draft",
        created_by=operator_id,
    )
    session.add(row)
    session.flush()
    investigation = session.get(ResearchInvestigation, finding.investigation_id)
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="poc.template_created", outcome="allowed", entity_type="poc_template", entity_id=row.id, details={"execution_enabled": False})
    session.commit()
    session.refresh(row)
    return row


def create_report(session: Session, investigation_id: str, operator_id: str, spec: ReportCreate) -> ResearchReport:
    investigation = _owned_investigation(session, investigation_id, operator_id)
    evidence_ids = list(dict.fromkeys(spec.evidence_ids))
    if _owned_observation_ids(session, operator_id, evidence_ids) != set(evidence_ids):
        raise ControlPlaneError("report evidence contains missing or unowned observations", 404)
    findings = list(session.scalars(select(FindingCandidate).where(FindingCandidate.investigation_id == investigation.id).order_by(FindingCandidate.created_at)))
    findings_json = [{"id": finding.id, "title": finding.title, "severity": finding.severity, "status": finding.status} for finding in findings]
    row = ResearchReport(
        investigation_id=investigation.id,
        title=spec.title,
        summary=spec.summary,
        limitations=spec.limitations,
        findings_json=findings_json,
        evidence_ids=evidence_ids,
        status="draft",
        created_by=operator_id,
    )
    session.add(row)
    session.flush()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="report.created", outcome="allowed", entity_type="report", entity_id=row.id, details={"finding_count": len(findings_json), "validated_count": sum(1 for item in findings_json if item["status"] == "validated")})
    session.commit()
    session.refresh(row)
    return row


def create_reproduction_record(session: Session, investigation_id: str, operator_id: str, spec: ReproductionRecordCreate) -> ReproductionRecord:
    investigation = _owned_investigation(session, investigation_id, operator_id)
    if spec.finding_id:
        finding = session.scalar(select(FindingCandidate).where(FindingCandidate.id == spec.finding_id, FindingCandidate.investigation_id == investigation.id))
        if finding is None:
            raise ControlPlaneError("finding not found in investigation", 404)
    row = ReproductionRecord(
        investigation_id=investigation.id,
        finding_id=spec.finding_id,
        isolation=spec.isolation,
        outcome=spec.outcome,
        summary=spec.summary,
        limits=dict(spec.limits),
        evidence_digest=spec.evidence_digest,
        created_by=operator_id,
    )
    session.add(row)
    session.flush()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="reproduction.record_created", outcome="allowed", entity_type="reproduction", entity_id=row.id, details={"outcome": row.outcome, "isolation": row.isolation, "execution_performed": False})
    session.commit()
    session.refresh(row)
    return row


def create_research_profile(session: Session, project_id: str, operator_id: str, spec: ResearchProfileCreate) -> ResearchProfile:
    project = session.scalar(select(Project).where(Project.id == project_id, Project.owner_id == operator_id))
    if project is None:
        raise ControlPlaneError("project not found", 404)
    row = ResearchProfile(
        project_id=project.id,
        name=spec.name,
        cpu_limit_percent=spec.cpu_limit_percent,
        memory_limit_mb=spec.memory_limit_mb,
        wall_time_seconds=spec.wall_time_seconds,
        process_limit=spec.process_limit,
        storage_limit_mb=spec.storage_limit_mb,
        status="inactive",
        created_by=operator_id,
    )
    session.add(row)
    session.flush()
    _audit(session, project_id=project.id, actor_id=operator_id, action="research_profile.created", outcome="allowed", entity_type="research_profile", entity_id=row.id, details={"worker_enabled": False})
    session.commit()
    session.refresh(row)
    return row
