# z3r0 Security Research Platform

This Python application is a human-governed control plane that complements the
repository's original shell toolkit. It does not replace those scripts or
autonomously run them.

## Status and boundaries

Implemented slices include project scope and budget policy, operator approvals,
an investigation and hypothesis lifecycle, offline evidence import and
endpoint intelligence, bounded HTTPX and Playwright gateways, candidate finding
validation, and persistence for advisory/source claims, reproduction metadata,
draft-only PoCs, reports, and inactive research profiles.

These are not a complete autonomous research platform. Advisory feeds and
repository ingestion are not active; PoCs are not executable; research profiles
do not launch workers; there is no fuzzing worker, dashboard, or model-provider
supervisor. Imported scanner results and inferred endpoint data remain
unverified observations.

The HTTP gateway checks DNS answers before the request but does not pin the
transport to those addresses. DNS rebinding is therefore a known egress-control
gap. Real-browser egress enforcement has not received dedicated end-to-end
validation. Do not use either gateway against targets until these controls have
been independently tested and the deployment's authorization and network
boundaries are established.

## Requirements

- Python 3.11+
- SQLite for local development and tests
- PostgreSQL for shared or production deployments

## Local setup

Run the following commands from this `platform/` directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Set `Z3R0_API_TOKEN` in `.env` to a unique, strong local value before starting
the API. Do not commit `.env`. `Z3R0_OPERATOR_ID` identifies the single local
operator; this project does not provide multi-user identity or role management.

Apply migrations and start the API bound to loopback:

```bash
alembic upgrade head
uvicorn z3r0_platform.api:app --env-file .env --host 127.0.0.1 --port 8000
```

For browser execution, install the Playwright browser separately:

```bash
playwright install chromium
```

For PostgreSQL, set `Z3R0_DATABASE_URL` to the deployment's PostgreSQL URL.
Do not expose the development API to an untrusted network; its shared API token
is not production authentication or secret management.

## API capabilities

All endpoints except `/health` require the `X-API-Token` header. The API
supports:

- Projects with explicit host/scheme/port scope and bounded budgets.
- Task proposals, approval/revocation, and authorization-time policy checks.
- Versioned JSON evidence import, offline Nuclei JSONL and OpenAPI 3 JSON
  parsing, provenance digests, redaction, and project-scoped deduplication.
- Offline asset/endpoint projections derived only from imported evidence.
- Authorized bounded HTTPX requests and cURL export; redirects are disabled.
- Bounded Playwright scenarios for approved browser tasks.
- Evidence-linked finding candidates, independent validation records, and
  human review gates.
- Candidate advisory/source claims, reproduction records, draft-only PoC
  templates, report drafts, and inactive resource profiles.

These endpoints persist proposals and observations; they do not activate
external advisory acquisition, source fetching, PoC execution, fuzzing, or
isolated workers. Consult `IMPLEMENTATION_ROADMAP.md` for phase status and
remaining acceptance work.

## Validation

```bash
pytest
```

The tests use synthetic/local data and do not establish safe egress behavior
against real targets or production-grade isolation.
