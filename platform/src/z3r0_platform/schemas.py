from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
import json
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ActionKind(StrEnum):
    OFFLINE_ANALYSIS = "offline_analysis"
    ARTIFACT_IMPORT = "artifact_import"
    RECONNAISSANCE = "reconnaissance"
    HTTP_REQUEST = "http_request"
    BROWSER_ACTION = "browser_action"
    AUTHENTICATED_TEST = "authenticated_test"
    RATE_LIMIT_TEST = "rate_limit_test"
    POC_EXECUTION = "poc_execution"


APPROVAL_REQUIRED_ACTIONS = frozenset(
    {
        ActionKind.RECONNAISSANCE,
        ActionKind.HTTP_REQUEST,
        ActionKind.BROWSER_ACTION,
        ActionKind.AUTHENTICATED_TEST,
        ActionKind.RATE_LIMIT_TEST,
        ActionKind.POC_EXECUTION,
    }
)


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def normalize_host(value: str) -> str:
    host = value.strip().rstrip(".")
    if not host or any(char in host for char in "/\\@%?#") or "*" in host:
        raise ValueError("host must be a literal hostname or IP address")

    try:
        return ip_address(host).compressed.lower()
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host):
            raise ValueError("invalid IP address")

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("host is not valid IDNA") from exc

    if len(ascii_host) > 253:
        raise ValueError("host is too long")
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("host contains an invalid DNS label")
    return ascii_host


def normalize_target_url(value: str) -> tuple[str, str, str, int]:
    if any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("target URL cannot contain whitespace or control characters")
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
            raise ValueError("target URL must be an absolute HTTP(S) URL")
        if parts.username is not None or parts.password is not None:
            raise ValueError("target URL cannot contain userinfo")
        if parts.query or parts.fragment:
            raise ValueError("target URL cannot contain a query string or fragment")
        if parts.netloc.endswith(":"):
            raise ValueError("target URL has an invalid port")
        host_value = parts.hostname
        if not host_value:
            raise ValueError("target URL must include a hostname")
        host = normalize_host(host_value)
        scheme = parts.scheme.lower()
        parsed_port = parts.port
        port = parsed_port if parsed_port is not None else (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("target URL"):
            raise
        raise ValueError("target URL is malformed") from exc

    if not 1 <= port <= 65535:
        raise ValueError("target URL port must be between 1 and 65535")
    if parts.path and (parts.path.startswith("//") or "\\" in parts.path):
        raise ValueError("target URL path is ambiguous")
    normalized_netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        normalized_netloc = f"{normalized_netloc}:{port}"
    normalized = urlunsplit((scheme, normalized_netloc, parts.path or "/", "", ""))
    return normalized, host, scheme, port


class ScopeInput(InputModel):
    host: str = Field(min_length=1, max_length=253)
    scheme: str
    port: int | None = Field(default=None, ge=1, le=65535)
    include_subdomains: bool = False
    expires_at: datetime

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return normalize_host(value)

    @field_validator("scheme")
    @classmethod
    def validate_scheme(cls, value: str) -> str:
        scheme = value.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("scope scheme must be http or https")
        return scheme

    @field_validator("expires_at")
    @classmethod
    def validate_expiry_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_scope(self) -> "ScopeInput":
        if self.port is None:
            object.__setattr__(self, "port", 443 if self.scheme == "https" else 80)
        try:
            ip_address(self.host)
            if self.include_subdomains:
                raise ValueError("IP scopes cannot include subdomains")
        except ValueError as exc:
            if str(exc) == "IP scopes cannot include subdomains":
                raise
        if self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("scope expiry must be in the future")
        return self


class ProjectCreate(InputModel):
    name: str = Field(min_length=1, max_length=200)
    budget_limit_units: int = Field(gt=0, le=1_000_000_000)
    iteration_limit: int = Field(gt=0, le=1_000_000)
    scopes: list[ScopeInput] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def reject_duplicate_scopes(self) -> "ProjectCreate":
        keys = [(scope.host, scope.scheme, scope.port) for scope in self.scopes]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate host, scheme, and port scope entries are not allowed")
        return self


class ProjectResponse(BaseModel):
    id: str
    owner_id: str
    name: str
    status: str
    budget_limit_units: int
    budget_reserved_units: int
    iteration_limit: int
    iterations_reserved: int
    created_at: datetime
    scopes: list["ScopeResponse"]

    model_config = ConfigDict(from_attributes=True)


class ScopeResponse(BaseModel):
    id: str
    host: str
    scheme: str
    port: int
    include_subdomains: bool
    expires_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TaskCreate(InputModel):
    action: ActionKind
    target_url: str = Field(min_length=1, max_length=2048)
    objective: str = Field(min_length=1, max_length=2000)
    requested_budget_units: int = Field(gt=0, le=1_000_000_000)
    requested_iterations: int = Field(gt=0, le=1_000_000)

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        return normalize_target_url(value)[0]


class TaskResponse(BaseModel):
    id: str
    project_id: str
    scope_id: str
    action: ActionKind
    target_url: str
    objective: str
    requested_budget_units: int
    requested_iterations: int
    status: str
    created_at: datetime
    authorized_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class InvestigationStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    REJECTED = "rejected"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    DISPROVED = "disproved"
    NEEDS_REVIEW = "needs_review"


class HypothesisEvidenceRelation(StrEnum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    NEEDS_VALIDATION = "needs_validation"
    VALIDATED = "validated"
    REJECTED = "rejected"


class ValidationVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdvisoryCorrelationCreate(InputModel):
    advisory_id: str = Field(min_length=1, max_length=32)
    package_name: str = Field(min_length=1, max_length=255)
    affected_version: str = Field(min_length=1, max_length=255)
    source_name: str = Field(min_length=1, max_length=80)
    source_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    retrieved_at: datetime
    evidence_ids: list[str] = Field(min_length=1, max_length=20)


class SourceClaimCreate(InputModel):
    repository: str = Field(min_length=1, max_length=2048)
    revision: str = Field(min_length=1, max_length=128)
    claim_type: str = Field(pattern=r"^(sink|patch|dependency|static-lead)$")
    file_path: str | None = Field(default=None, max_length=2048)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    statement: str = Field(min_length=1, max_length=2000)
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_range(self) -> "SourceClaimCreate":
        if self.line_start is not None and self.line_end is not None and self.line_end < self.line_start:
            raise ValueError("line_end cannot precede line_start")
        return self


class SafePocCreate(InputModel):
    title: str = Field(min_length=1, max_length=200)
    format: str = Field(pattern=r"^(text|http|yaml)$")
    content: str = Field(min_length=1, max_length=65536)
    approved_target: str = Field(min_length=1, max_length=2048)


class ReportCreate(InputModel):
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=10000)
    limitations: str = Field(min_length=1, max_length=10000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class ReproductionRecordCreate(InputModel):
    finding_id: str | None = Field(default=None, max_length=36)
    isolation: str = Field(pattern=r"^(process|container|virtual-machine|offline-fixture)$")
    outcome: str = Field(pattern=r"^(pending|succeeded|failed|blocked)$")
    summary: str = Field(min_length=1, max_length=2000)
    limits: dict[str, object] = Field(default_factory=dict, max_length=50)
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ResearchProfileCreate(InputModel):
    name: str = Field(min_length=1, max_length=200)
    cpu_limit_percent: int = Field(ge=1, le=100)
    memory_limit_mb: int = Field(ge=16, le=65536)
    wall_time_seconds: int = Field(ge=1, le=86400)
    process_limit: int = Field(ge=1, le=100)
    storage_limit_mb: int = Field(ge=1, le=1048576)


class FindingCreate(InputModel):
    hypothesis_id: str | None = Field(default=None, max_length=36)
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=80)
    statement: str = Field(min_length=1, max_length=2000)
    impact: str = Field(min_length=1, max_length=2000)
    severity: FindingSeverity
    evidence_ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator("evidence_ids")
    @classmethod
    def validate_unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("evidence IDs must be unique")
        return value


class FindingReview(InputModel):
    status: FindingStatus

    @model_validator(mode="after")
    def validate_review_status(self) -> "FindingReview":
        if self.status not in {FindingStatus.VALIDATED, FindingStatus.REJECTED, FindingStatus.NEEDS_VALIDATION}:
            raise ValueError("review status must be needs_validation, validated, or rejected")
        return self


class IndependentValidationCreate(InputModel):
    verdict: ValidationVerdict
    summary: str = Field(min_length=1, max_length=2000)
    reproducible: bool
    supporting_evidence_ids: list[str] = Field(min_length=1, max_length=20)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_ids(self) -> "IndependentValidationCreate":
        combined = self.supporting_evidence_ids + self.contradicting_evidence_ids
        if len(set(combined)) != len(combined):
            raise ValueError("validation evidence IDs must be unique")
        return self


class ProposalStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class InvestigationStateChange(InputModel):
    status: InvestigationStatus


class HypothesisCreate(InputModel):
    category: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    statement: str = Field(min_length=1, max_length=2000)
    expected_vulnerable_behavior: str = Field(min_length=1, max_length=2000)
    expected_secure_behavior: str = Field(min_length=1, max_length=2000)
    potential_impact: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    supporting_evidence_ids: list[str] = Field(min_length=1, max_length=20)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_evidence_ids(self) -> "HypothesisCreate":
        combined = self.supporting_evidence_ids + self.contradicting_evidence_ids
        if len(set(combined)) != len(combined):
            raise ValueError("evidence IDs must be unique and cannot support and contradict together")
        return self


class HypothesisEvidenceCreate(InputModel):
    observation_id: str = Field(min_length=1, max_length=36)
    relation: HypothesisEvidenceRelation


class HypothesisStatusChange(InputModel):
    status: HypothesisStatus


class ProposalCreate(InputModel):
    hypothesis_id: str = Field(min_length=1, max_length=36)
    action: ActionKind
    rationale: str = Field(min_length=1, max_length=2000)
    budget_units: int = Field(gt=0, le=1_000_000_000)
    iteration_units: int = Field(gt=0, le=1_000_000)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator("evidence_ids")
    @classmethod
    def validate_unique_evidence(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("evidence IDs must be unique")
        return value


class ProposalReview(InputModel):
    status: ProposalStatus

    @field_validator("status")
    @classmethod
    def validate_final_decision(cls, value: ProposalStatus) -> ProposalStatus:
        if value == ProposalStatus.PENDING_REVIEW:
            raise ValueError("review status must be accepted or rejected")
        return value


class HypothesisEvidenceResponse(BaseModel):
    observation_id: str
    relation: HypothesisEvidenceRelation
    kind: EvidenceRecordKind
    subject: str
    record_sha256: str


class HypothesisResponse(BaseModel):
    id: str
    investigation_id: str
    category: str
    statement: str
    expected_vulnerable_behavior: str
    expected_secure_behavior: str
    potential_impact: str
    confidence: float
    status: HypothesisStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    evidence: list[HypothesisEvidenceResponse]


class ProposalResponse(BaseModel):
    id: str
    investigation_id: str
    hypothesis_id: str
    scope_id: str
    target_url: str
    action: ActionKind
    rationale: str
    budget_units: int
    iteration_units: int
    status: ProposalStatus
    created_by: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    evidence_ids: list[str]


class InvestigationResponse(BaseModel):
    id: str
    project_id: str
    task_id: str
    scope_id: str
    target_url: str
    objective: str
    status: InvestigationStatus
    budget_limit_units: int
    budget_used_units: int
    iteration_limit: int
    iterations_used: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    hypotheses: list[HypothesisResponse]
    proposals: list[ProposalResponse]


class HttpRequestCreate(InputModel):
    method: str = Field(pattern=r"^[A-Za-z]+$", max_length=16)
    url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict, max_length=50)
    body: str | None = Field(default=None, max_length=65536)
    timeout_ms: int = Field(default=5000, ge=100, le=30000)
    max_response_bytes: int = Field(default=262144, ge=1024, le=1048576)

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        return method

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return normalize_target_url(value)[0]

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        sensitive = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)$", re.I)
        normalized: dict[str, str] = {}
        for key, header_value in value.items():
            if not key or len(key) > 100 or "\r" in key or "\n" in key:
                raise ValueError("invalid HTTP header name")
            if "\r" in header_value or "\n" in header_value:
                raise ValueError("invalid HTTP header value")
            if sensitive.search(key):
                raise ValueError("sensitive credential headers are not accepted in request payloads")
            if key.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                raise ValueError("transport-controlled headers are not accepted")
            normalized[key] = header_value
        return normalized

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > 65536:
            raise ValueError("HTTP body exceeds 65536 UTF-8 bytes")
        return value


class BrowserActionCreate(InputModel):
    action: str = Field(pattern=r"^(navigate|click|type|wait)$")
    url: str | None = Field(default=None, max_length=2048)
    selector: str | None = Field(default=None, max_length=2048)
    text_ref: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    timeout_ms: int = Field(default=5000, ge=100, le=30000)

    @model_validator(mode="after")
    def validate_action_shape(self) -> "BrowserActionCreate":
        if self.action == "navigate":
            if self.url is None:
                raise ValueError("navigate requires url")
            object.__setattr__(self, "url", normalize_target_url(self.url)[0])
        elif self.action in {"click", "type"}:
            if self.selector is None:
                raise ValueError(f"{self.action} requires selector")
        if self.action == "type" and self.text_ref is None:
            raise ValueError("type requires text_ref")
        if self.action != "type" and self.text_ref is not None:
            raise ValueError("text_ref is only allowed for type")
        return self


class BrowserScenarioCreate(InputModel):
    actions: list[BrowserActionCreate] = Field(min_length=1, max_length=10)


class BrowserActionResponse(BaseModel):
    ordinal: int
    action: str
    outcome: str
    detail: str | None = None


class BrowserExecutionResponse(BaseModel):
    id: str
    task_id: str
    outcome: str
    actions: list[BrowserActionResponse]
    blocked_requests: int
    final_url: str | None
    created_at: datetime


class HttpRequestResponse(BaseModel):
    id: str
    task_id: str
    method: str
    url: str
    status_code: int | None
    outcome: str
    redirect_count: int
    resolved_addresses: list[str]
    request_bytes: int
    response_bytes: int
    response_sha256: str | None
    error: str | None
    created_at: datetime


class ApprovalCreate(InputModel):
    max_budget_units: int = Field(gt=0, le=1_000_000_000)
    max_iterations: int = Field(gt=0, le=1_000_000)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        if value.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            raise ValueError("approval expiry must be in the future")
        return value.astimezone(timezone.utc)


class EvidenceRunStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class EvidenceRecordKind(StrEnum):
    ASSET = "asset"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    PARAMETER = "parameter"
    API_OPERATION = "api_operation"
    FINDING_CANDIDATE = "finding_candidate"
    NOTE = "note"


class EvidenceObservationInput(InputModel):
    kind: EvidenceRecordKind
    subject: str = Field(min_length=1, max_length=2048)
    source_record_id: str | None = Field(default=None, max_length=128)
    data: dict[str, object] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def validate_data_size(cls, value: dict[str, object]) -> dict[str, object]:
        try:
            serialized = json.dumps(value, ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("evidence data must contain JSON values only") from exc
        if len(serialized.encode("utf-8")) > 65_536:
            raise ValueError("evidence data exceeds 65536 UTF-8 bytes")
        if _json_depth(value) > 16:
            raise ValueError("evidence data exceeds maximum nesting depth")
        return value


def _json_depth(value: object, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max((_json_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_json_depth(item, depth + 1) for item in value), default=depth)
    return depth


class EvidenceImport(InputModel):
    schema_version: str = Field(pattern=r"^1$")
    source_tool: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    source_version: str | None = Field(default=None, max_length=80)
    artifact_name: str | None = Field(default=None, max_length=255)
    source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    run_status: EvidenceRunStatus
    coverage_note: str | None = Field(default=None, max_length=2000)
    observations: list[EvidenceObservationInput] = Field(max_length=1000)

    @field_validator("artifact_name")
    @classmethod
    def validate_artifact_name(cls, value: str | None) -> str | None:
        if value is not None and ("/" in value or "\\" in value or value in {".", ".."}):
            raise ValueError("artifact_name must be a filename, not a path")
        return value


class EvidenceObservationResponse(BaseModel):
    id: str
    ordinal: int
    kind: EvidenceRecordKind
    subject: str
    source_record_id: str | None
    record_sha256: str
    data: dict[str, object]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceArtifactResponse(BaseModel):
    id: str
    project_id: str
    payload_sha256: str
    source_sha256: str | None
    source_tool: str
    source_version: str | None
    artifact_name: str | None
    schema_version: str
    run_status: EvidenceRunStatus
    record_count: int
    redacted_field_count: int
    imported_by: str
    imported_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceImportResponse(BaseModel):
    artifact: EvidenceArtifactResponse
    observations: list[EvidenceObservationResponse]
    duplicate: bool


class EvidenceArtifactDetailResponse(BaseModel):
    artifact: EvidenceArtifactResponse
    observations: list[EvidenceObservationResponse]


class EvidenceSourceFormat(StrEnum):
    NUCLEI_JSONL = "nuclei-jsonl"
    OPENAPI_JSON = "openapi-json"


class EvidenceSourceImport(InputModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    source_format: EvidenceSourceFormat
    source_text: str = Field(min_length=1)
    run_status: EvidenceRunStatus
    source_version: str | None = Field(default=None, max_length=80)
    artifact_name: str | None = Field(default=None, max_length=255)
    coverage_note: str | None = Field(default=None, max_length=2000)

    @field_validator("source_text")
    @classmethod
    def validate_source_size(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 2_097_152:
            raise ValueError("source_text exceeds 2097152 UTF-8 bytes")
        return value

    @field_validator("artifact_name")
    @classmethod
    def validate_artifact_name(cls, value: str | None) -> str | None:
        if value is not None and ("/" in value or "\\" in value or value in {".", ".."}):
            raise ValueError("artifact_name must be a filename, not a path")
        return value
