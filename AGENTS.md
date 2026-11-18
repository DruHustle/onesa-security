# Onesa Security — engineering rules

Source ownership: **this repository only**. Do not modify Onesa AI, Identity, Portal, Robot, Industrial or unrelated repositories as a side-effect. Adopt the Onesa shared identity and design conventions through reviewed, versioned contracts, not copied secrets, internal credentials or direct database access.

## Release discipline

The integration lead controls shared contracts, threat-model changes and acceptance evidence. Use feature PRs, security review, automated tests and explicit GO/NO-GO for every module. Prefer reviewed `dev → staging → main` promotion after creating those environment branches and branch rules. No auto-merge, policy bypass, forced history rewrite or production deployment by default. Do not confuse merged code, successful CI, staging probes and production qualification. Local test fixtures prove only their own scope.

## Security invariants

- Onesa Identity (`https://auth.onesa.eu/`) signs access tokens; API validates issuer, signature, audience, expiry and membership. An Auth0 login alone never grants an Onesa Security tenant role.
- `X-Onesa-Organization` selects a scope but never grants membership. Every data query includes that scope; PostgreSQL RLS enforces it separately. Never connect the API using a superuser/BYPASSRLS role.
- Collectors use unique high-entropy, revocable, expiring credentials, with verified mTLS mandatory outside isolated local development. Client-supplied verification headers are not trusted. Do not make the dev exception public.
- Treat prompts, documents, tool returns, telemetry and other external data as untrusted. Tool execution is blocked in the foundation; textual claims of privilege never authorize actions. Do not log raw AI prompts, secrets or uploaded records.
- High-risk actions fail closed on missing security dependencies. No automatic changes to operating systems, production infrastructure, OT machinery, drones or robots.
- No fabricated detections, live dashboards, compliance claims, signed agent claims or certified control effectiveness. Mark incomplete features planned.
- Never add private credentials, production backups, endpoint identifiers or customer event data to Git/Actions. Limit services to reviewed TLS origins, bound requests, and minimal privileges.

## Implementation ownership

- Platform: `services/api/app/{auth,database,models,bootstrap}.py`, migrations.
- AI: `services/api/app/guardrails.py` and gateway endpoints.
- Detection: `services/api/app/detection.py`, normalized ingestion and alert endpoints.
- Endpoint: `agents/linux` read-only preview only; OS-specific native support blocked pending qualification.
- Frontend: `apps/web`, Auth0 SDK BFF, accessible UI, real-data labeling.
- Release: `.github/workflows`, `docs/security`, integration tests, operator runbooks.

Do not weaken authorization to make tests green. Use `pytest` for API tests and pinned Node/npm runtime for the frontend. The frontend must receive a committed lockfile and a clean hosted build before release. Resolve security findings instead of suppressing CI.
