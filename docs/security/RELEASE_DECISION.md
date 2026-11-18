# Initial release decision — 2026-11-18

**Overall: NO-GO for customer production.** Functional foundation source and local automated tests do not qualify full enterprise cybersecurity claims.

| Module | Implemented now | Evidence / remaining gate | Decision |
|---|---|---|---|
| Platform and identity | JWT verifier, tenant membership checks, role enforcement, RLS SQL migration | Offline authorization tests; real Auth0 audience, PostgreSQL RLS and browser callback untested | NO-GO |
| AI Security | Deterministic inspect endpoint and optional fixed-provider nonstreaming proxy; tools denied | Fixtures pass; adversarial red-team, real provider, latency/false-positive benchmarking absent | NO-GO |
| Enterprise security | Reported inventory via registered collector | One Linux read-only preview, no verified enterprise connector/vuln manager | NO-GO |
| Detection and SOC | Real event persistence, 3 rule IDs, explainable alerts, case status and audit metadata | Unit/integration tests pass; throughput, correlated sources and real production telemetry untested | NO-GO |
| Endpoint and OS security | Read-only Linux inventory preview | No mTLS native signed agent/offline queue; Windows/macOS unimplemented | NO-GO |
| Remediation and upgrades | Not implemented | Dry-run, approval, rollback, testing all missing | NO-GO |
| Compliance and commercial | Planned UI only | No framework evidence, billing or contract qualification | NO-GO |

**Qualify next:** obtain a signed identity integration approval and staging client, validate PostgreSQL RLS with least-privilege service role, implement ingress mTLS against a real collector, create locked frontend dependencies, run full hosted CI/quality gates, implement backup/restore, risk acceptance and independent security review. Do not create DNS records or deploy live APIs based solely on this document.

## CI receipt

Initial draft PR #1, run [44291034754](https://github.com/DruHustle/onesa-security/actions/runs/44291034754) reported failure on all three jobs, with no listed job steps and logs unavailable through the connected API. This provides **no evidence that source tests executed in GitHub Actions**, and no defensible attribution to specific code failures. Inspect repository Actions permissions, runner capacity/billing and GitHub's workflow annotations before retrying. Do not change branch protection or suppress scanner failures to get a green badge.

## Additional reviewed-scope candidate (same date, not production evidence)

- **Finding lifecycle:** enrolled collectors can submit asset-scoped, evidence-referenced findings. Operators can classify false positives and risks; collector recurrence reopens a reviewed finding. A collector report is **not** proof of exploitation. RLS migration 002 enforces tenant context on findings and proposals.
- **Security upgrades:** analysts may author impact/rollback proposals. A separate organization owner must approve or reject; there is **no execution dispatcher**, even on approval. Production change control, patch deployment, rollback and impact tests are still NOT IMPLEMENTED.
- **Compliance:** source counts are explicitly labeled partial engineering evidence, with zero verified framework controls; no claims of certification or legal compliance.
- **Operating system:** optional Linux read-only SSH configuration hints cannot prove effective sshd posture; no signed service package, privileged telemetry or mTLS enrollment is supplied.
- **Real PostgreSQL:** a disposable GitHub Actions test role and schema setup have been added, but this does not constitute a passed test until an actual hosted runner executes the full suite and RLS negative tests.
- **AI:** untrusted callers cannot submit upstream `system`-role messages. This does not qualify protection against all injection attacks.

The scope increase does not change overall production **NO-GO**. The live web build is Vercel-team protected; missing Auth0 client and backend credentials prevent authenticated workflow verification. No customer domain or API origin was activated.

## Infrastructure configuration and verification update — 2026-11-18

This update supersedes the earlier **infrastructure-status** statements in this document; it does not change the product's production **NO-GO** decision.

- **Frontend domain:** `security.onesa.eu` is an owned, verified Vercel project domain. Cloudflare has a DNS-only CNAME to Vercel's returned target. Vercel reports DNS correctly configured and HTTPS/TLS validation passed in an independent HTTP probe.
- **Protected deployment:** the Vercel production-target frontend build on reviewed main `5eb37ec5` passed and serves the protected custom domain. Anonymous `/`, `/api/healthz`, `/api/readyz`, and `/auth/login` requests return HTTP 302 to Vercel Authentication; this establishes **access-gate presence**, not application readiness.
- **Vercel environment:** reviewed non-secret `AUTH0_DOMAIN=auth.onesa.eu` and `OIDC_AUDIENCE=https://security-api.onesa.eu` are configured for production/preview; `APP_BASE_URL=https://security.onesa.eu` is production-only. Independent 32-byte cryptographically generated `AUTH0_SECRET` values were stored as **sensitive**, scoped separately to production/preview. These secret additions require a new build to become active.
- **Identity incomplete:** no dedicated Security `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` are configured. No authenticated Onesa Security login, registered callback, product grant or tenant-membership acceptance has been performed. A session secret is not a substitute for an OAuth client credential.
- **API incomplete:** `security-api.onesa.eu` has no DNS record or commissioned Oracle service behind it. No `ONESA_API_ORIGIN` or tenant identifier is configured in Vercel. Do not fabricate or copy these values from another product; actual deployment, RLS and enrollment need operator evidence.
- **CI evidence:** [main run 44394014307](https://github.com/DruHustle/onesa-security/actions/runs/44394014307) passed all three jobs; 38 tests on the API job, real disposable PostgreSQL with FORCE RLS, a restricted Dockerized API smoke test, seven live Next.js fail-closed checks and synthetic p99 guardrail 46 µs. No production provider, operating-system EDR or load claim follows from these results.
- **Current deployment limitation:** a direct follow-up Vercel API deployment request returned HTTP 402 `api-deployments-free-per-day`; do not upgrade or charge the team without explicit approval. Normal Git-integrated deployments continue to be the approved branch-based release path.

The existing Onesa Identity repository recognizes the `security` product and its web registration return, but a user grant alone does not create an Onesa Security tenant membership. Complete dedicated application registration, strict membership mapping, API/DB/mTLS deployment and authenticated browser tests before assigning customer GO.
