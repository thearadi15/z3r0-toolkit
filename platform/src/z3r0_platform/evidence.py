import hashlib
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import (
    EvidenceArtifact,
    EvidenceObservation,
    Project,
    utc_now,
)
from z3r0_platform.policy import ControlPlaneError, _audit, get_owned_project
from z3r0_platform.schemas import EvidenceImport

_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|authorization|cookie|credential|"
    r"private[_-]?key|client[_-]?secret|session[_-]?id|api[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_VALUE = re.compile(
    r"([?&](?:access[_-]?token|api[_-]?key|auth|code|credential|key|password|"
    r"secret|session|token)=)[^&#\s]*",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)
_URL_USERINFO = re.compile(r"(https?://)[^/\s@]+@", re.IGNORECASE)


def _redact(value: object, key: str | None = None) -> tuple[object, int]:
    if key is not None and _SENSITIVE_KEY.search(key) and value is not None:
        return "[REDACTED]", 1
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        count = 0
        for child_key, child_value in value.items():
            clean_value, child_count = _redact(child_value, str(child_key))
            redacted[str(child_key)] = clean_value
            count += child_count
        return redacted, count
    if isinstance(value, list):
        redacted_list: list[object] = []
        count = 0
        for item in value:
            clean_value, child_count = _redact(item)
            redacted_list.append(clean_value)
            count += child_count
        return redacted_list, count
    if isinstance(value, str):
        redacted = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
        redacted = _SENSITIVE_QUERY_VALUE.sub(r"\1[REDACTED]", redacted)
        redacted = _BEARER_VALUE.sub("Bearer [REDACTED]", redacted)
        return redacted, int(redacted != value)
    return value, 0


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def import_evidence(
    session: Session,
    project_id: str,
    operator_id: str,
    spec: EvidenceImport,
) -> tuple[EvidenceArtifact, bool]:
    project: Project = get_owned_project(session, project_id, operator_id)
    cleaned_observations: list[dict[str, object]] = []
    redacted_count = 0

    for observation in spec.observations:
        clean_subject, subject_count = _redact(observation.subject)
        clean_data, data_count = _redact(observation.data)
        redacted_count += subject_count + data_count
        cleaned_observations.append(
            {
                "kind": observation.kind.value,
                "subject": clean_subject,
                "source_record_id": observation.source_record_id,
                "data": clean_data,
            }
        )

    clean_coverage_note, coverage_count = _redact(spec.coverage_note or "")
    redacted_count += coverage_count
    canonical_payload = {
        "schema_version": spec.schema_version,
        "source_tool": spec.source_tool,
        "source_version": spec.source_version,
        "artifact_name": spec.artifact_name,
        "source_sha256": spec.source_sha256,
        "run_status": spec.run_status.value,
        "coverage_note": clean_coverage_note or None,
        "observations": cleaned_observations,
    }
    payload_sha256 = hashlib.sha256(_canonical_json(canonical_payload)).hexdigest()

    existing = session.scalar(
        select(EvidenceArtifact)
        .where(
            EvidenceArtifact.project_id == project.id,
            EvidenceArtifact.payload_sha256 == payload_sha256,
        )
        .options(selectinload(EvidenceArtifact.observations))
    )
    if existing is not None:
        _audit(
            session,
            project_id=project.id,
            actor_id=operator_id,
            action="evidence.imported",
            outcome="duplicate",
            entity_type="evidence",
            entity_id=existing.id,
            details={"payload_sha256": payload_sha256},
        )
        session.commit()
        return existing, True

    artifact = EvidenceArtifact(
        project_id=project.id,
        payload_sha256=payload_sha256,
        source_sha256=spec.source_sha256,
        source_tool=spec.source_tool,
        source_version=spec.source_version,
        artifact_name=spec.artifact_name,
        schema_version=spec.schema_version,
        run_status=spec.run_status.value,
        coverage_note=clean_coverage_note or None,
        record_count=len(cleaned_observations),
        redacted_field_count=redacted_count,
        imported_by=operator_id,
        imported_at=utc_now(),
    )
    session.add(artifact)
    session.flush()

    for ordinal, observation in enumerate(cleaned_observations):
        session.add(
            EvidenceObservation(
                artifact_id=artifact.id,
                ordinal=ordinal,
                kind=observation["kind"],
                subject=observation["subject"],
                source_record_id=observation["source_record_id"],
                record_sha256=hashlib.sha256(_canonical_json(observation)).hexdigest(),
                data=observation["data"],
            )
        )

    _audit(
        session,
        project_id=project.id,
        actor_id=operator_id,
        action="evidence.imported",
        outcome="allowed",
        entity_type="evidence",
        entity_id=artifact.id,
        details={
            "payload_sha256": payload_sha256,
            "record_count": artifact.record_count,
            "run_status": artifact.run_status,
            "redacted_field_count": redacted_count,
        },
    )
    session.commit()
    session.refresh(artifact)
    artifact.observations
    return artifact, False


def get_owned_evidence(
    session: Session, artifact_id: str, operator_id: str
) -> EvidenceArtifact:
    artifact = session.scalar(
        select(EvidenceArtifact)
        .join(Project)
        .where(
            EvidenceArtifact.id == artifact_id,
            Project.owner_id == operator_id,
        )
        .options(selectinload(EvidenceArtifact.observations))
    )
    if artifact is None:
        raise ControlPlaneError("evidence artifact not found", 404)
    return artifact


def list_owned_evidence(
    session: Session, project_id: str, operator_id: str, limit: int
) -> list[EvidenceArtifact]:
    project = get_owned_project(session, project_id, operator_id)
    return list(
        session.scalars(
            select(EvidenceArtifact)
            .where(EvidenceArtifact.project_id == project.id)
            .order_by(EvidenceArtifact.imported_at.desc(), EvidenceArtifact.id)
            .limit(limit)
        )
    )
