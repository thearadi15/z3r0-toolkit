import hashlib
import json

from pydantic import ValidationError

from z3r0_platform.schemas import (
    EvidenceImport,
    EvidenceObservationInput,
    EvidenceRecordKind,
    EvidenceSourceFormat,
    EvidenceSourceImport,
)

_HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
)
_MAX_OBSERVATIONS = 1000


def parse_evidence_source(source: EvidenceSourceImport) -> EvidenceImport:
    source_bytes = source.source_text.encode("utf-8")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()

    try:
        if source.source_format == EvidenceSourceFormat.NUCLEI_JSONL:
            tool, _, observations = _parse_nuclei_jsonl(source.source_text)
            version = source.source_version
        else:
            tool, version, observations = _parse_openapi_json(source.source_text)
        return EvidenceImport(
            schema_version="1",
            source_tool=tool,
            source_version=version,
            artifact_name=source.artifact_name,
            source_sha256=source_sha256,
            run_status=source.run_status,
            coverage_note=source.coverage_note,
            observations=observations,
        )
    except ValidationError as exc:
        raise ValueError(
            "source produced evidence outside the supported schema or size limits"
        ) from exc
    except RecursionError as exc:
        raise ValueError("source exceeds the supported JSON nesting depth") from exc


def _parse_nuclei_jsonl(
    source_text: str,
) -> tuple[str, str | None, list[EvidenceObservationInput]]:
    observations: list[EvidenceObservationInput] = []
    for line_number, line in enumerate(source_text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Nuclei JSONL at line {line_number}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Nuclei record at line {line_number} must be a JSON object")

        info = record.get("info")
        if info is not None and not isinstance(info, dict):
            raise ValueError(f"Nuclei info at line {line_number} must be a JSON object")
        info = info or {}
        matched_at = record.get("matched-at")
        host = record.get("host")
        subject = matched_at if isinstance(matched_at, str) and matched_at else host
        if not isinstance(subject, str) or not subject:
            raise ValueError(f"Nuclei record at line {line_number} has no matched-at or host")

        data: dict[str, object] = {
            "source_format": "nuclei-jsonl",
            "template_id": _optional_string(record.get("template-id")),
            "scanner_name": _optional_string(info.get("name")),
            "scanner_severity": _optional_string(info.get("severity")),
            "tags": _string_list(info.get("tags")),
            "matcher_name": _optional_string(record.get("matcher-name")),
            "matched_at": _optional_string(matched_at),
            "host": _optional_string(host),
            "type": _optional_string(record.get("type")),
            "timestamp": _optional_string(record.get("timestamp")),
        }
        data = {key: value for key, value in data.items() if value is not None}
        observations.append(
            EvidenceObservationInput(
                kind=EvidenceRecordKind.FINDING_CANDIDATE,
                subject=subject,
                source_record_id=f"line:{line_number}",
                data=data,
            )
        )
        _check_observation_limit(len(observations))
    return "nuclei", None, observations


def _parse_openapi_json(
    source_text: str,
) -> tuple[str, str | None, list[EvidenceObservationInput]]:
    try:
        document = json.loads(source_text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid OpenAPI JSON document") from exc
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be a JSON object")
    openapi_version = document.get("openapi")
    if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
        raise ValueError("only OpenAPI 3.x JSON documents are supported")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI document must contain a paths object")

    observations: list[EvidenceObservationInput] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("OpenAPI path keys must begin with a slash")
        if not isinstance(path_item, dict):
            raise ValueError("OpenAPI path items must be JSON objects")
        if "$ref" in path_item:
            raise ValueError("OpenAPI path-item references are not dereferenced by this importer")

        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            raise ValueError("OpenAPI path parameters must be an array")
        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError("OpenAPI operations must be JSON objects")
            parameters = operation.get("parameters", [])
            if not isinstance(parameters, list):
                raise ValueError("OpenAPI operation parameters must be arrays")
            security = operation.get("security", document.get("security", []))
            if not isinstance(security, list):
                raise ValueError("OpenAPI security declarations must be arrays")

            data: dict[str, object] = {
                "source_format": "openapi-json",
                "method": method.upper(),
                "parameters": _combined_parameter_shapes(path_parameters, parameters),
                "response_codes": _response_codes(operation.get("responses", {})),
                "request_media_types": _content_types(
                    operation.get("requestBody", {})
                ),
                "security_requirement_declared": bool(security),
                "deprecated": operation.get("deprecated") is True,
            }
            unresolved_references = _operation_references(operation)
            if unresolved_references:
                data["unresolved_references"] = unresolved_references
            operation_id = _optional_string(operation.get("operationId"))
            summary = _optional_string(operation.get("summary"))
            tags = _string_list(operation.get("tags"))
            if operation_id is not None:
                data["operation_id"] = operation_id
            if summary is not None:
                data["summary"] = summary
            if tags:
                data["tags"] = tags

            source_id = operation_id or f"{method.upper()} {path}"
            observations.append(
                EvidenceObservationInput(
                    kind=EvidenceRecordKind.API_OPERATION,
                    subject=f"{method.upper()} {path}",
                    source_record_id=source_id[:128],
                    data=data,
                )
            )
            _check_observation_limit(len(observations))
    return "openapi", openapi_version, observations


def _parameter_shapes(parameters: list[object]) -> list[dict[str, object]]:
    shapes: list[dict[str, object]] = []
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise ValueError("OpenAPI parameter declarations must be objects")
        reference = _optional_string(parameter.get("$ref"))
        if reference is not None:
            shapes.append({"unresolved_reference": reference})
            continue
        name = _optional_string(parameter.get("name"))
        location = _optional_string(parameter.get("in"))
        if name is None or location is None:
            raise ValueError("OpenAPI parameter needs a name and in value")
        shape: dict[str, object] = {
            "name": name,
            "in": location,
            "required": parameter.get("required") is True,
        }
        schema = parameter.get("schema")
        if isinstance(schema, dict):
            schema_type = _optional_string(schema.get("type"))
            schema_format = _optional_string(schema.get("format"))
            schema_reference = _optional_string(schema.get("$ref"))
            if schema_type is not None:
                shape["type"] = schema_type
            if schema_format is not None:
                shape["format"] = schema_format
            if schema_reference is not None:
                shape["unresolved_schema_reference"] = schema_reference
        shapes.append(shape)
    return shapes


def _combined_parameter_shapes(
    path_parameters: list[object], operation_parameters: list[object]
) -> list[dict[str, object]]:
    merged: dict[tuple[str, str], dict[str, object]] = {}
    unresolved: list[dict[str, object]] = []
    for parameter in path_parameters + operation_parameters:
        shape = _parameter_shapes([parameter])[0]
        if "unresolved_reference" in shape:
            unresolved.append(shape)
        else:
            merged[(str(shape["name"]), str(shape["in"]))] = shape
    return [*merged.values(), *unresolved]


def _response_codes(value: object) -> list[str]:
    if not isinstance(value, dict):
        raise ValueError("OpenAPI responses must be an object")
    return sorted(str(code) for code in value)


def _content_types(value: object) -> list[str]:
    if value == {}:
        return []
    if not isinstance(value, dict):
        raise ValueError("OpenAPI requestBody must be an object")
    if "$ref" in value:
        return []
    content = value.get("content", {})
    if not isinstance(content, dict):
        raise ValueError("OpenAPI requestBody content must be an object")
    return sorted(str(media_type) for media_type in content)


def _operation_references(operation: dict[str, object]) -> list[str]:
    references: list[str] = []
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        reference = _optional_string(request_body.get("$ref"))
        if reference is not None:
            references.append(reference)
    responses = operation.get("responses")
    if isinstance(responses, dict):
        for response in responses.values():
            if isinstance(response, dict):
                reference = _optional_string(response.get("$ref"))
                if reference is not None:
                    references.append(reference)
    return list(dict.fromkeys(references))


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:50]


def _check_observation_limit(count: int) -> None:
    if count > _MAX_OBSERVATIONS:
        raise ValueError(f"source exceeds the {_MAX_OBSERVATIONS} observation limit")
