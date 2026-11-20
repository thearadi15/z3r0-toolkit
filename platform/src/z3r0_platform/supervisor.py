from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import (
    EvidenceArtifact,
    EvidenceObservation,
    HypothesisEvidence,
    Project,
    ProposalEvidence,
    ResearchHypothesis,
    ResearchInvestigation,
    ResearchProposal,
    ResearchTask,
    utc_now,
)
from z3r0_platform.policy import ControlPlaneError, _audit, _find_scope
from z3r0_platform.schemas import (
    HypothesisCreate,
    HypothesisStatus,
    HypothesisStatusChange,
    InvestigationStateChange,
    InvestigationStatus,
    ProposalCreate,
    ProposalReview,
)


def _owned_task(session: Session, task_id: str, operator_id: str) -> ResearchTask:
    task = session.scalar(
        select(ResearchTask)
        .join(Project)
        .where(ResearchTask.id == task_id, Project.owner_id == operator_id)
        .options(selectinload(ResearchTask.project).selectinload(Project.scopes), selectinload(ResearchTask.scope))
    )
    if task is None:
        raise ControlPlaneError("task not found", 404)
    return task


def create_investigation(session: Session, task_id: str, operator_id: str) -> ResearchInvestigation:
    task = _owned_task(session, task_id, operator_id)
    if task.status != "authorized":
        raise ControlPlaneError("investigations require an authorized task", 409)
    existing = session.scalar(select(ResearchInvestigation).where(ResearchInvestigation.task_id == task.id))
    if existing is not None:
        raise ControlPlaneError("investigation already exists for task", 409)
    scope = task.scope
    now = utc_now()
    investigation = ResearchInvestigation(
        project_id=task.project_id,
        task_id=task.id,
        scope_id=scope.id,
        target_url=task.target_url,
        objective=task.objective,
        status="active",
        budget_limit_units=task.requested_budget_units,
        budget_used_units=0,
        iteration_limit=task.requested_iterations,
        iterations_used=0,
        created_by=operator_id,
        created_at=now,
        updated_at=now,
    )
    session.add(investigation)
    session.flush()
    _audit(session, project_id=task.project_id, actor_id=operator_id, action="investigation.created", outcome="allowed", entity_type="investigation", entity_id=investigation.id, details={"task_id": task.id})
    session.commit()
    session.refresh(investigation)
    return investigation


def get_owned_investigation(session: Session, investigation_id: str, operator_id: str) -> ResearchInvestigation:
    investigation = session.scalar(
        select(ResearchInvestigation)
        .join(Project)
        .where(ResearchInvestigation.id == investigation_id, Project.owner_id == operator_id)
        .options(
            selectinload(ResearchInvestigation.hypotheses).selectinload(ResearchHypothesis.evidence_links).selectinload(HypothesisEvidence.observation),
            selectinload(ResearchInvestigation.proposals).selectinload(ResearchProposal.evidence_links).selectinload(ProposalEvidence.observation),
        )
    )
    if investigation is None:
        raise ControlPlaneError("investigation not found", 404)
    return investigation


def change_investigation_status(session: Session, investigation_id: str, operator_id: str, spec: InvestigationStateChange) -> ResearchInvestigation:
    investigation = get_owned_investigation(session, investigation_id, operator_id)
    current = InvestigationStatus(investigation.status)
    target = spec.status
    allowed = {
        InvestigationStatus.ACTIVE: {InvestigationStatus.PAUSED, InvestigationStatus.COMPLETED, InvestigationStatus.REJECTED},
        InvestigationStatus.PAUSED: {InvestigationStatus.ACTIVE, InvestigationStatus.COMPLETED, InvestigationStatus.REJECTED},
        InvestigationStatus.COMPLETED: set(),
        InvestigationStatus.REJECTED: set(),
    }
    if target not in allowed[current]:
        raise ControlPlaneError("invalid investigation state transition", 409)
    investigation.status = target.value
    investigation.updated_at = utc_now()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="investigation.status_changed", outcome="allowed", entity_type="investigation", entity_id=investigation.id, details={"from": current.value, "to": target.value})
    session.commit()
    session.refresh(investigation)
    return investigation


def create_hypothesis(session: Session, investigation_id: str, operator_id: str, spec: HypothesisCreate) -> ResearchHypothesis:
    investigation = get_owned_investigation(session, investigation_id, operator_id)
    if investigation.status != "active":
        raise ControlPlaneError("hypotheses require an active investigation", 409)

    observation_ids = set(spec.supporting_evidence_ids + spec.contradicting_evidence_ids)
    observations = list(session.scalars(select(EvidenceObservation).join(EvidenceArtifact, EvidenceArtifact.id == EvidenceObservation.artifact_id).join(Project, Project.id == EvidenceArtifact.project_id).where(EvidenceObservation.id.in_(observation_ids), Project.owner_id == operator_id)))
    found = {observation.id for observation in observations}
    missing = observation_ids - found
    if missing:
        raise ControlPlaneError("one or more evidence observations are not owned or do not exist", 404)

    hypothesis = ResearchHypothesis(
        investigation_id=investigation.id,
        category=spec.category,
        statement=spec.statement,
        expected_vulnerable_behavior=spec.expected_vulnerable_behavior,
        expected_secure_behavior=spec.expected_secure_behavior,
        potential_impact=spec.potential_impact,
        confidence=spec.confidence,
        status="proposed",
        created_by=operator_id,
    )
    session.add(hypothesis)
    session.flush()
    for observation_id in spec.supporting_evidence_ids:
        session.add(HypothesisEvidence(hypothesis_id=hypothesis.id, observation_id=observation_id, relation="supporting"))
    for observation_id in spec.contradicting_evidence_ids:
        session.add(HypothesisEvidence(hypothesis_id=hypothesis.id, observation_id=observation_id, relation="contradicting"))
    investigation.updated_at = utc_now()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="hypothesis.created", outcome="allowed", entity_type="hypothesis", entity_id=hypothesis.id, details={"supporting": len(spec.supporting_evidence_ids), "contradicting": len(spec.contradicting_evidence_ids)})
    session.commit()
    session.refresh(hypothesis)
    hypothesis.evidence_links
    return hypothesis


def change_hypothesis_status(session: Session, hypothesis_id: str, operator_id: str, spec: HypothesisStatusChange) -> ResearchHypothesis:
    hypothesis = session.scalar(
        select(ResearchHypothesis)
        .join(ResearchInvestigation)
        .join(Project)
        .where(ResearchHypothesis.id == hypothesis_id, Project.owner_id == operator_id)
        .options(selectinload(ResearchHypothesis.investigation), selectinload(ResearchHypothesis.evidence_links))
    )
    if hypothesis is None:
        raise ControlPlaneError("hypothesis not found", 404)
    if hypothesis.investigation.status != "active":
        raise ControlPlaneError("hypothesis transitions require an active investigation", 409)
    current = HypothesisStatus(hypothesis.status)
    target = spec.status
    allowed = {
        HypothesisStatus.PROPOSED: {HypothesisStatus.INVESTIGATING, HypothesisStatus.NEEDS_REVIEW, HypothesisStatus.DISPROVED},
        HypothesisStatus.INVESTIGATING: {HypothesisStatus.NEEDS_REVIEW, HypothesisStatus.DISPROVED},
        HypothesisStatus.DISPROVED: set(),
        HypothesisStatus.NEEDS_REVIEW: {HypothesisStatus.INVESTIGATING, HypothesisStatus.DISPROVED},
    }
    if target not in allowed[current]:
        raise ControlPlaneError("invalid hypothesis state transition", 409)
    hypothesis.status = target.value
    hypothesis.updated_at = utc_now()
    hypothesis.investigation.updated_at = hypothesis.updated_at
    _audit(session, project_id=hypothesis.investigation.project_id, actor_id=operator_id, action="hypothesis.status_changed", outcome="allowed", entity_type="hypothesis", entity_id=hypothesis.id, details={"from": current.value, "to": target.value})
    session.commit()
    session.refresh(hypothesis)
    return hypothesis


def create_proposal(session: Session, investigation_id: str, operator_id: str, spec: ProposalCreate) -> ResearchProposal:
    investigation = get_owned_investigation(session, investigation_id, operator_id)
    if investigation.status != "active":
        raise ControlPlaneError("proposals require an active investigation", 409)
    hypothesis = session.scalar(select(ResearchHypothesis).where(ResearchHypothesis.id == spec.hypothesis_id, ResearchHypothesis.investigation_id == investigation.id))
    if hypothesis is None:
        raise ControlPlaneError("hypothesis not found in investigation", 404)
    if spec.budget_units > investigation.budget_limit_units - investigation.budget_used_units:
        raise ControlPlaneError("proposal exceeds investigation budget", 409)
    if spec.iteration_units > investigation.iteration_limit - investigation.iterations_used:
        raise ControlPlaneError("proposal exceeds investigation iteration limit", 409)
    observation_ids = set(spec.evidence_ids)
    observations = list(session.scalars(select(EvidenceObservation).join(EvidenceArtifact, EvidenceArtifact.id == EvidenceObservation.artifact_id).join(Project, Project.id == EvidenceArtifact.project_id).where(EvidenceObservation.id.in_(observation_ids), Project.owner_id == operator_id)))
    if {observation.id for observation in observations} != observation_ids:
        raise ControlPlaneError("proposal evidence contains missing or unowned observations", 404)
    proposal = ResearchProposal(
        investigation_id=investigation.id,
        hypothesis_id=hypothesis.id,
        scope_id=investigation.scope_id,
        target_url=investigation.target_url,
        action=spec.action.value,
        rationale=spec.rationale,
        budget_units=spec.budget_units,
        iteration_units=spec.iteration_units,
        status="pending_review",
        created_by=operator_id,
    )
    session.add(proposal)
    session.flush()
    for observation_id in spec.evidence_ids:
        session.add(ProposalEvidence(proposal_id=proposal.id, observation_id=observation_id))
    investigation.updated_at = utc_now()
    _audit(session, project_id=investigation.project_id, actor_id=operator_id, action="proposal.created", outcome="allowed", entity_type="proposal", entity_id=proposal.id, details={"hypothesis_id": hypothesis.id, "budget_units": spec.budget_units, "iteration_units": spec.iteration_units})
    session.commit()
    session.refresh(proposal)
    proposal.evidence_links
    return proposal


def review_proposal(session: Session, proposal_id: str, operator_id: str, spec: ProposalReview) -> ResearchProposal:
    proposal = session.scalar(
        select(ResearchProposal)
        .join(ResearchInvestigation)
        .join(Project)
        .where(ResearchProposal.id == proposal_id, Project.owner_id == operator_id)
        .options(selectinload(ResearchProposal.investigation), selectinload(ResearchProposal.evidence_links))
    )
    if proposal is None:
        raise ControlPlaneError("proposal not found", 404)
    if proposal.status != "pending_review":
        raise ControlPlaneError("proposal has already been reviewed", 409)
    if proposal.investigation.status != "active":
        raise ControlPlaneError("proposal review requires an active investigation", 409)
    scope = proposal.investigation.scope
    if _find_scope([scope], proposal.target_url) is None:
        raise ControlPlaneError("proposal target is outside active scope", 403)

    if spec.status.value == "accepted":
        investigation = proposal.investigation
        if proposal.budget_units > investigation.budget_limit_units - investigation.budget_used_units:
            raise ControlPlaneError("proposal exceeds current investigation budget", 409)
        if proposal.iteration_units > investigation.iteration_limit - investigation.iterations_used:
            raise ControlPlaneError("proposal exceeds current investigation iteration limit", 409)

    proposal.status = spec.status.value
    proposal.reviewed_by = operator_id
    proposal.reviewed_at = utc_now()
    proposal.investigation.updated_at = proposal.reviewed_at
    _audit(session, project_id=proposal.investigation.project_id, actor_id=operator_id, action="proposal.reviewed", outcome="allowed", entity_type="proposal", entity_id=proposal.id, details={"status": proposal.status})
    session.commit()
    session.refresh(proposal)
    return proposal
