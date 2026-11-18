# Onesa Security — Oracle API deployment qualification

**Not a production authorization.** Do not deploy before source-locked CI, backup
recovery, least-privilege PostgreSQL roles, tenant isolation, ingress and Auth0
have been accepted by an authorized operator.

- The API image is built from the reviewed GitHub commit and recorded with an
  immutable image digest (`ONESA_SECURITY_IMAGE`). Do not use `:latest`.
- Provision PostgreSQL independently with a migration owner, a separate
  `onesa_api` runtime account with `NOBYPASSRLS`, TLS and tested backups.
  Apply `001_initial.sql`, `002_findings_and_approvals.sql` and
  `003_ai_agent_spans.sql` **in order only once to a new database**. Existing
  installations must apply only unapplied migrations after reviewing schema state.
- Keep `/etc/onesa/security/api.env` outside Git and readable only by
  authorized host operators. It must provide an approved `DATABASE_URL`,
  `OIDC_ISSUER=https://auth.onesa.eu/`, exact registered API audience,
  and optional separately approved model gateway details. This file is a
  host-local secret source; do not publish its contents.
- Run `docker compose --env-file /etc/onesa/security/deploy.env
  -f deploy/compose.oracle.yaml up -d --wait` only with an exact local
  image and `ONESA_SECURITY_HOST_PORT` set in the deploy env file.
- The service binds to **loopback only**. Never map its port publicly.
  An independent reviewed HTTPS ingress is necessary for browser API calls.
  Collector event endpoints **fail closed** because the ASGI scope requires
  verified mTLS from trusted ingress middleware; a client header cannot
  claim that verification. This template does not implement client mTLS.
- Verify `GET /healthz` returns liveness, `GET /readyz` returns a
  non-bypass role and all FORCE RLS migrations (never read 200 as an auth
  acceptance). Then run actual signed Onesa user session, tenant denial,
  collector certificate, event, alert, and backup/restore acceptance.
  The web app exposes its own `/api/readyz` to report configuration
  and API readiness without leaking internal origins.
- The Vercel frontend must be linked to the reviewed GitHub revision,
  protected with Vercel Authentication during qualification, and have a
  distinct confidential Auth0 application configured in protected Vercel
  environment variables. DNS `security.onesa.eu` is already assigned to the **Vercel Authentication-protected** frontend. This is a restricted engineering deployment, not a customer release. Do not disable Vercel Authentication, publish `security-api.onesa.eu` or connect a customer before the API/identity end-to-end gates pass.

If any gate fails, keep customer ingress and payment/telemetry ingestion off.
No command in this runbook rotates credentials, modifies machines or provisions
a customer-facing service without explicit operator control.
