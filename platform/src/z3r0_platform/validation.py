from sqlalchemy import select
from sqlalchemy.orm import Session

from z3r0_platform.models import (
    EvidenceArtifact,
    EvidenceObservation,
    FindingCandidate,
    FindingEvidence,
    IndependentValidation,
    Project,
    ResearchHypothesis,
    ResearchInvestigation,
    ValidationEvidence,
    utc_now,
)
from z3r0_platform.policy import ControlPlaneError, _audit
from z3r0_platform.schemas import (
    FindingCreate,
    FindingReview,
    FindingStatus,
    IndependentValidationCreate,
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


def _owned_observation_ids(session: Session, operator_id: str, observation_ids: set[str]) -> set[str]:
    if not observation_ids:
        return set()
    observations = list(session.scalars(
        select(EvidenceObservation)
        .join(EvidenceArtifact, EvidenceArtifact.id == EvidenceObservation.artifact_id)
        .join(Project, Project.id == EvidenceArtifact.project_id)
        .where(EvidenceObservation.id.in_(observation_ids), Project.owner_id == operator_id)
    ))
    return {observation.id for observation in observations}


def create_finding(session: Session, investigation_id: str, operator_id: str, spec: FindingCreate) -> FindingCandidate:
    investigation = _owned_investigation(session, investigation_id, operator_id)
    if investigation.status != "active":
        raise ControlPlaneError("findings require an active investigation", 409)
    if spec.hypothesis_id:
        hypothesis = session.scalar(
            select(ResearchHypothesis).where(
                ResearchHypothesis.id == spec.hypothesis_id,
                ResearchHypothesis.investigation_id == investigation.id,
            )
        )
        if hypothesis is None:
            raise ControlPlaneError("hypothesis not found in investigation", 404)

    evidence_ids = set(spec.evidence_ids)
    if _owned_observation_ids(session, operator_id, evidence_ids) != evidence_ids:
        raise ControlPlaneError("finding evidence contains missing or unowned observations", 404)

    finding = FindingCandidate(
        investigation_id=investigation.id,
        hypothesis_id=spec.hypothesis_id,
        title=spec.title,
        category=spec.category,
        statement=spec.statement,
        impact=spec.impact,
        severity=spec.severity.value,
        status="candidate",
        created_by=operator_id,
    )
    session.add(finding)
    session.flush()
    for observation_id in spec.evidence_ids:
        session.add(FindingEvidence(finding_id=finding.id, observation_id=observation_id, relation="supporting"))
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="finding.created", outcome="allowed", entity_type="finding", entity_id=finding.id, details={"severity": finding.severity, "evidence_count": len(spec.evidence_ids)})
    session.commit()
    session.refresh(finding)
    return finding


def get_owned_finding(session: Session, finding_id: str, operator_id: str) -> FindingCandidate:
    finding = session.scalar(
        select(FindingCandidate)
        .join(ResearchInvestigation)
        .join(Project)
        .where(FindingCandidate.id == finding_id, Project.owner_id == operator_id)
    )
    if finding is None:
        raise ControlPlaneError("finding not found", 404)
    return finding


def add_independent_validation(session: Session, finding_id: str, operator_id: str, spec: IndependentValidationCreate) -> IndependentValidation:
    finding = get_owned_finding(session, finding_id, operator_id)
    if finding.status not in {"candidate", "needs_validation"}:
        raise ControlPlaneError("finding is not available for validation", 409)
    evidence_ids = set(spec.supporting_evidence_ids + spec.contradicting_evidence_ids)
    if _owned_observation_ids(session, operator_id, evidence_ids) != evidence_ids:
        raise ControlPlaneError("validation evidence contains missing or unowned observations", 404)

    validation = IndependentValidation(
        finding_id=finding.id,
        validator_id=operator_id,
        verdict=spec.verdict.value,
        summary=spec.summary,
        reproducible=spec.reproducible,
    )
    session.add(validation)
    session.flush()
    for observation_id in spec.supporting_evidence_ids:
        session.add(ValidationEvidence(validation_id=validation.id, observation_id=observation_id, relation="supporting"))
    for observation_id in spec.contradicting_evidence_ids:
        session.add(ValidationEvidence(validation_id=validation.id, observation_id=observation_id, relation="contradicting"))

    finding.status = "needs_validation"
    finding.updated_at = utc_now()
    investigation = session.get(ResearchInvestigation, finding.investigation_id)
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="finding.validation_added", outcome="allowed", entity_type="finding", entity_id=finding.id, details={"verdict": validation.verdict, "reproducible": validation.reproducible})
    session.commit()
    session.refresh(validation)
    return validation


def review_finding(session: Session, finding_id: str, operator_id: str, spec: FindingReview) -> FindingCandidate:
    finding = get_owned_finding(session, finding_id, operator_id)
    if finding.status == "validated" or finding.status == "rejected":
        raise ControlPlaneError("finding has already been reviewed", 409)

    if spec.status == FindingStatus.VALIDATED:
        confirmation = session.scalar(
            select(IndependentValidation).where(
                IndependentValidation.finding_id == finding.id,
                IndependentValidation.verdict == "confirmed",
                IndependentValidation.reproducible.is_(True),
            )
        )
        if confirmation is None:
            raise ControlPlaneError("validated findings require reproducible independent confirmed evidence", 409)

    finding.status = spec.status.value
    finding.reviewed_by = operator_id
    finding.reviewed_at = utc_now()
    finding.updated_at = finding.reviewed_at
    investigation = session.get(ResearchInvestigation, finding.investigation_id)
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="finding.reviewed", outcome="allowed", entity_type="finding", entity_id=finding.id, details={"status": finding.status})
    session.commit()
    session.refresh(finding)
    return finding
