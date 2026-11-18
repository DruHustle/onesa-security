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
