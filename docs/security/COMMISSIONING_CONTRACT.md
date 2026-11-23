# Onesa Security — exact configuration and commissioning contract

Status: **protected web host configured; production user/security workflows NOT qualified** (2026-11-18).

## Existing verified settings

The authoritative Cloudflare zone `onesa.eu` contains DNS-only CNAME `security.onesa.eu` → Vercel's recommended project CNAME. Vercel reports project domain **verified**, HTTPS correctly configured, and Vercel Authentication **all deployments**. Browser requests from unauthenticated clients redirect to Vercel sign-in. Keep that protection until independent product acceptance.

Vercel contains non-secret `AUTH0_DOMAIN`, `OIDC_AUDIENCE` and production `APP_BASE_URL`. Separately generated 32-byte `AUTH0_SECRET` values are stored as **sensitive**, production versus preview. Never print, export or reuse the secret across Onesa products.

## Missing external authorization and actual commissioning

**Auth0 tenant / Onesa Identity:** register a dedicated **Onesa Security confidential web application** with the existing `https://auth.onesa.eu/` issuer. The production callback is **exactly** `https://security.onesa.eu/auth/callback`. Set the approved web origin to `https://security.onesa.eu`, and use the supported Auth0 sign-out route and app login URI. Register `https://security-api.onesa.eu` as its restricted API audience. Configure `AUTH0_CLIENT_ID` as non-public server config and `AUTH0_CLIENT_SECRET` as a separate sensitive production value inside the Vercel project—never copy another Onesa product's client secret or paste it into Git, chat, logs or frontend bundles. Use a separate approved staging client and callback for preview. Verify actual MFA, token audience, callback, logout and access denial.

**API, database and collectors:** deploy the reviewed FastAPI image on the existing Onesa Oracle backend through a tested private service account. Apply migrations 001 → 002 → 003 with a **different migration owner** from the runtime `NOBYPASSRLS` database role. Validate backup/restore and the restricted API container `/readyz` using the real database. Implement a trusted TLS/mTLS ingress for collector traffic; client-supplied TLS headers cannot constitute certificate validation. Only after the service is independently healthy should the exact `security-api.onesa.eu` route and DNS record be configured.

**First tenant:** bootstrap the approved stable Onesa UG tenant UUID and actual verified Auth0 subject using `app.bootstrap` on the commissioned database. The Onesa Identity `security` grant is distinct from tenant membership; both must be verified for the intended user and operator roles. Add `ONESA_ORGANIZATION_ID` and `ONESA_API_ORIGIN` to the Vercel project **only after** that deployment and grants exist.

The Security API requires the signed Onesa product assertion and checks current tenant membership on every request. Verify that the dedicated client supplies a signed Onesa MFA timestamp for analysts, tenant administrators and owners. Collector administration, guardrail policy changes and remediation approval require a completed factor within five minutes. Exercise missing and expired factors alongside a successful reauthentication before activating the client.

## Acceptance sequence

1. GitHub Actions on the exact source commit: 3/3 jobs green, including real disposable PostgreSQL RLS, actual Docker image, source security scans, Next.js build and fail-closed runtime tests
2. Vercel custom domain HTTPS, certificate and authenticated routing, with Vercel deployment protection still enabled
3. Signed live Onesa account login and owner product grant, valid API audience, tenant membership and forbidden cross-tenant access tests
4. Real API request → PostgreSQL event/finding → alert → analyst case workflow with appropriate audit records, plus verified collector TLS/agent revocation
5. Backup/restore, operational monitoring, hostile-input/mTLS/tenant pen-test, latency and recovery evidence; only then issue an evidence-backed customer GO

Do not mark anonymous redirect, webpage build, historical CI or synthetic telemetry as evidence of working production security.
