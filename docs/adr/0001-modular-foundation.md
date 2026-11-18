# ADR-0001 — Onesa Security functional foundation

Status: Proposed / initial implementation. Integration lead: Onesa Security engineering. Date: 2026-11-18.

## Decision

Use one modular FastAPI control-plane service backed by PostgreSQL and an isolated Next.js/React BFF frontend. Store tenant membership, collector credentials (digests only), minimal inventory, event metadata, explainable alerts, audit entries and AI policies. Begin with one developer Linux inventory collector and guarded OpenAI-compatible nonstreaming chat proxy. Use existing Auth0 custom issuer `https://auth.onesa.eu/` and a dedicated audience and confidential browser client. Do not create another account/password database.

## Rationale

Separating control plane, identity, telemetry source and provider runtime establishes practical boundaries without an expensive premature microservice fleet. PostgreSQL RLS plus explicit API filters is a two-layer control; tests using SQLite verify API-scoping only and never prove PostgreSQL role/RLS operation. A distinct migration owner and an API role without BYPASSRLS are mandatory. Collectors cannot claim mutual TLS from a client-controlled HTTP header; only a trusted ASGI TLS-termination integration can grant the verification scope. If that is missing, production collection is denied.

## Deferred decisions

- Durable queue, partitioned/searchable event store and production retention evidence
- Native signed endpoint agent, platform entitlements, encrypted local buffering and mTLS device onboarding
- Policy compilation, provider adapters/streaming, action approval, agent sandboxing and RAG authorization
- Enterprise discovery connectors and read-only IAM/cloud posture
- Remediation orchestration, secure rollbacks and change calendars
- Immutable external audit anchoring and evidence/object storage
- EU residency, key management, backup/recovery and commercial entitlement model

No deferred capability is marketed as working in this release.
