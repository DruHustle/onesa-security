# Onesa Security

**Onesa UG · defensive cybersecurity platform · initial functional foundation (NOT production-qualified)**

Canonical repository: `DruHustle/onesa-security`. Planned UI: `security.onesa.eu`; planned API: `security-api.onesa.eu`. These names are targets only, **not evidence of deployment or live protection**.

## What works in this source

The first vertical slice connects signed Onesa Identity access tokens and local product memberships with a tenant-isolated PostgreSQL schema, a real data API, a server-rendered Next.js dashboard, a baseline AI inspection engine, a normalized event ingestion path, explainable detection rules, alert triage and an authorized Linux inventory preview. No fake findings are seeded into the interface. `apps/web` labels unsupported modules as planned.

| Capability | Current behavior | Limitation |
|---|---|---|
| Tenant identity | Auth0 JWT issuer/audience/signature validation, product-specific membership roles and per-request PostgreSQL RLS scope | New API audience/client/Onesa approval must be registered and tested |
| AI security | Allow/Block/Redact decisions, simple injection and credential-pattern detection, fixed approved HTTPS upstream nonstreaming proxy | Pattern matching cannot prevent all injections; no tool execution, streaming, RAG source auth or AI evaluation dashboard |
| Threat detection | Authorized collector events, deduplication, sign-in burst detection, privilege/persistence alerts and evidence IDs | No durable telemetry queue, long-term event search or proven large-scale correlation |
| Security operations | Alert queue, analyst status changes, dispositions and audit activity metadata | No automatic response or external SOC connector |
| Asset inventory | Scoped reporting, encrypted-transit requirement, credential expiry/revocation | Linux collector is **developer preview**, no OS event agent/secure updates/mTLS client certificates |
| Commercial / compliance | Module navigation and release blockers | Not enabled, no compliance certification or billing claim |

## Architecture

```mermaid
flowchart LR
    Browser[Next.js browser] -->|Auth0 confidential OIDC| IdP[Onesa Identity / Auth0]
    Browser -->|Host-only BFF session| BFF[Next.js BFF]
    BFF -->|Audience-scoped access token| API[FastAPI control plane]
    API -->|Tenant-scoped session + RLS| PG[(PostgreSQL)]
    Collector[Read-only Linux dev collector] -->|Scoped token, production mTLS gate| API
    API -->|Approved static HTTPS target| AI[AI model provider]
```

No application shares Onesa Identity's account database. No browser receives the upstream model API key. A user-provided organization ID is never an authorization grant. The application database role cannot bypass RLS. Production collector ingestion remains **fail-closed** until a separately verified mTLS ingress integration is built.

## Development and tests

See [developer runbook](docs/runbooks/LOCAL_DEVELOPMENT.md). Minimal offline tests:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e './services/api[test]'
(cd services/api && pytest -q)
(cd agents/linux && python -m unittest -q test_collector.py)
```

A local Docker Compose stack is in [`compose.dev.yaml`](compose.dev.yaml); it requires explicit local DB secrets and a dedicated Auth0 developer application and never publishes API/DB to the network. See `.env.example` for variable names, not secrets. Use actual signed Identity tokens for browser acceptance; the API tests use isolated subject fixtures for DB authorization checks only.

## Major entry points

- `services/api/app/main.py`: FastAPI endpoints (all writes role- or collector-scoped)
- `services/api/migrations/001_initial.sql`: versioned PostgreSQL DDL, RLS policies
- `services/api/tests/`: offline authorization/detection/guardrail integration tests
- `apps/web/`: Next.js 16 App Router + Auth0 SDK v4 server-side token BFF
- `agents/linux/`: read-only preview; not a native endpoint product
- `.github/workflows/verify.yml`: preliminary CI; lockfile, security scans, hosted browser and performance qualification still required
- `docs/security/THREAT_MODEL.md`: trusted boundaries and current security gaps
- `docs/security/RELEASE_DECISION.md`: evidence-based per-module NO-GO
- `AGENTS.md`: integration, authoring and security invariants

## Release contract

The overall release is **NO-GO** for customer production. An API unit test result is not an endpoint integration acceptance, and a successful UI build is not security approval. Local regression run: **10 API tests passed, 1 Linux unit test passed**. The first GitHub Actions PR run reported failure for every job before any job steps appeared, and downloadable logs were unavailable; the hosted verification result is therefore not qualified.

The remaining hard gates include dedicated Auth0 audience and browser callback, actual PostgreSQL RLS test against the least-privilege role, enforced client mTLS and secure enrollment, complete OWASP-style AI security evaluation, real OS-specific agent tests, audit immutability and recovery, throughput/latency benchmarks, hosted UI qualification and dependency locks/CI review.

Do not create DNS, enable paid services, install endpoint components on customer machines, run production scans or claim regulatory compliance based on this foundation. See the release decision for scope-by-scope gates.

## Continued implementation scope (2026-11-18)

The review branch also implements source-referenced finding ingestion, analyst review, two-person non-executing remediation proposals and evidence-only compliance counts. No customer protections are implied by these screens. Apply SQL migrations `001_initial.sql` then `002_findings_and_approvals.sql` as the migration principal, with an application role that **cannot bypass RLS**, before running the API. Never let the API runtime user own the schema or execute migrations.

API endpoints added: `GET /v1/findings`, `POST /v1/collector/findings`, `POST /v1/findings/{id}/resolve`, `GET/POST /v1/remediation-proposals`, `POST /v1/remediation-proposals/{id}/decision`, `GET /v1/compliance/readiness`. Collector evidence is reported—not independent verification. Remediation approval cannot trigger a remote command. Authentication remains Onesa Identity via Auth0; membership remains application-local and requires explicit bootstrap.

Run Python tests in `services/api` with `python -m pytest -q` and the developer Linux tests in `agents/linux` with `python -m unittest -q test_collector.py test_posture.py`. CI includes disposable PostgreSQL RLS checks that require actual runner execution to count as evidence. The Next.js deployment may build on Vercel, but missing `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`, `APP_BASE_URL`, API endpoint and authorized tenant means the website cannot be treated as operational.
