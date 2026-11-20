from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from z3r0_platform.models import (
    EvidenceArtifact,
    EvidenceObservation,
    EndpointEvidence,
    IntelligenceAsset,
    IntelligenceEndpoint,
    utc_now,
)
from z3r0_platform.schemas import normalize_host, normalize_target_url
from z3r0_platform.policy import ControlPlaneError, _audit, _find_scope, get_owned_project


def _endpoint_from_observation(observation: EvidenceObservation, project_scopes: list[object]) -> tuple[dict[str, object] | None, dict[str, object]]:
    data = observation.data if isinstance(observation.data, dict) else {}
    method = str(data.get("method") or "GET").upper()
    if observation.kind == "api_operation":
        parts = observation.subject.split(" ", 1)
        if len(parts) == 2:
            method = parts[0].upper()
            path = parts[1]
        else:
            path = observation.subject
        return {
            "host": None,
            "scheme": None,
            "port": None,
            "method": method,
            "path": path,
            "parameter_shape": {"parameters": data.get("parameters", [])},
            "origin_declared": False,
        }, data

    subject = observation.subject
    try:
        _, host, scheme, port = normalize_target_url(subject)
    except ValueError:
        return None, data
    if _find_scope(project_scopes, subject) is None:
        return None, data
    parts = urlsplit(subject)
    path = parts.path or "/"
    if observation.kind == "endpoint":
        method = str(data.get("method") or method).upper()
    else:
        method = "UNKNOWN"
    return {
        "host": host,
        "scheme": scheme,
        "port": port,
        "method": method,
        "path": path,
        "parameter_shape": {"parameters": data.get("parameters", [])},
        "origin_declared": True,
    }, data


def rebuild_intelligence(session: Session, project_id: str, operator_id: str) -> dict[str, int]:
    project = get_owned_project(session, project_id, operator_id)
    observations = list(
        session.scalars(
            select(EvidenceObservation)
            .join(EvidenceArtifact, EvidenceArtifact.id == EvidenceObservation.artifact_id)
            .where(EvidenceArtifact.project_id == project.id)
            .order_by(EvidenceObservation.created_at, EvidenceObservation.id)
        )
    )

    now = utc_now()
    session.query(EndpointEvidence).filter(
        EndpointEvidence.endpoint_id.in_(select(IntelligenceEndpoint.id).where(IntelligenceEndpoint.project_id == project.id))
    ).delete(synchronize_session=False)
    session.query(IntelligenceEndpoint).where(IntelligenceEndpoint.project_id == project.id).delete(synchronize_session=False)
    session.query(IntelligenceAsset).where(IntelligenceAsset.project_id == project.id).delete(synchronize_session=False)

    assets: dict[tuple[str, str | None, int | None], dict[str, object]] = {}
    endpoints: dict[tuple[str | None, str | None, int | None, str, str], dict[str, object]] = {}

    for observation in observations:
        data = observation.data if isinstance(observation.data, dict) else {}

        if observation.kind == "technology":
            for candidate in (observation.subject, data.get("host"), data.get("hostname")):
                if not isinstance(candidate, str):
                    continue
                try:
                    host = normalize_host(candidate)
                except ValueError:
                    continue
                key = (host, None, None)
                assets.setdefault(key, {"evidence_ids": [], "score": 0})
                assets[key]["evidence_ids"].append(observation.id)
                assets[key]["score"] = int(assets[key]["score"])+3

        endpoint_identity, data = _endpoint_from_observation(observation, project.scopes)
        if endpoint_identity is None:
            subject = observation.subject
            try:
                _, host, scheme, port = normalize_target_url(subject)
            except ValueError:
                continue
            if _find_scope(project.scopes, subject) is not None:
                key = (host, scheme, port)
                assets.setdefault(key, {"evidence_ids": [], "score": 0})
                assets[key]["evidence_ids"].append(observation.id)
                assets[key]["score"] = int(assets[key]["score"])+5
        else:
            host = endpoint_identity["host"]
            scheme = endpoint_identity["scheme"]
            port = endpoint_identity["port"]
            if host:
                key = (host, scheme, port)
                assets.setdefault(key, {"evidence_ids": [], "score": 0})
                assets[key]["evidence_ids"].append(observation.id)
                assets[key]["score"] = int(assets[key]["score"])+5

            method = str(endpoint_identity["method"])
            path = str(endpoint_identity["path"])
            key = (host, scheme, port, method, path)
            item = endpoints.setdefault(key, {
                "evidence_ids": [],
                "score": 0,
                "parameter_shape": endpoint_identity["parameter_shape"],
                "origin_declared": endpoint_identity["origin_declared"],
            })
            item["evidence_ids"].append(observation.id)
            item["score"] = int(item["score"])+{
                "finding_candidate": 25,
                "api_operation": 15,
                "endpoint": 10,
                "parameter": 8,
            }.get(observation.kind, 2)
            if isinstance(data, dict):
                if data.get("security_requirement_declared") is True:
                    item["score"] = int(item["score"])+10
                if data.get("parameters"):
                    item["score"] = int(item["score"])+8

            if any(marker in path for marker in ("{", "*", ":")):
                item["score"] = int(item["score"])+15

    asset_count = 0
    for (host, scheme, port), item in assets.items():
        evidence_ids = list(dict.fromkeys(item["evidence_ids"]))
        asset = IntelligenceAsset(
            project_id=project.id,
            host=host,
            scheme=scheme,
            port=port,
            evidence_count=len(evidence_ids),
            priority_score=min(100, int(item["score"])),
            data={"technology_observations": sum(1 for observation in observations if observation.kind == "technology" and host in (str(observation.subject), str((observation.data or {}).get("host", ""))) )},
            updated_at=now,
        )
        session.add(asset)
        asset_count += 1

    endpoint_count = 0
    for (host, scheme, port, method, path), item in endpoints.items():
        evidence_ids = list(dict.fromkeys(item["evidence_ids"]))
        endpoint = IntelligenceEndpoint(
            project_id=project.id,
            host=host,
            scheme=scheme,
            port=port,
            method=method,
            path=path,
            parameter_shape=item["parameter_shape"],
            evidence_count=len(evidence_ids),
            priority_score=min(100, int(item["score"])),
            origin_declared=bool(item["origin_declared"]),
            updated_at=now,
        )
        session.add(endpoint)
        session.flush()
        for observation_id in evidence_ids:
            session.add(EndpointEvidence(endpoint_id=endpoint.id, observation_id=observation_id, relation="supporting"))
        endpoint_count += 1

    _audit(
        session,
        project_id=project.id,
        actor_id=operator_id,
        action="intelligence.rebuilt",
        outcome="allowed",
        entity_type="project",
        entity_id=project.id,
        details={"asset_count": asset_count, "endpoint_count": endpoint_count, "observation_count": len(observations), "network_actions": 0},
    )
    session.commit()
    return {"asset_count": asset_count, "endpoint_count": endpoint_count, "observation_count": len(observations)}


def list_intelligence_assets(session: Session, project_id: str, operator_id: str, limit: int) -> list[IntelligenceAsset]:
    project = get_owned_project(session, project_id, operator_id)
    return list(session.scalars(select(IntelligenceAsset).where(IntelligenceAsset.project_id == project.id).order_by(IntelligenceAsset.priority_score.desc(), IntelligenceAsset.host).limit(limit)))


def list_intelligence_endpoints(session: Session, project_id: str, operator_id: str, limit: int) -> list[IntelligenceEndpoint]:
    project = get_owned_project(session, project_id, operator_id)
    return list(session.scalars(select(IntelligenceEndpoint).where(IntelligenceEndpoint.project_id == project.id).order_by(IntelligenceEndpoint.priority_score.desc(), IntelligenceEndpoint.path, IntelligenceEndpoint.method).limit(limit)))
