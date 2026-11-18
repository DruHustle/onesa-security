# Agent observability, guardrail performance, and SDK drift monitoring

## Agent execution-path tracing
Instrument agents with an authenticated analyst-authorized POST to `/v1/ai/agent-traces`.
The metadata contract includes UUID trace/span IDs, optional parent, stable agent reference,
execution phase, outcome, reported microseconds and timestamp. Never include prompt,
retrieval content, tool arguments, personal data, credentials or model output. Access is tenant
scoped; duplicated spans are rejected. The dashboard is a **refreshable, near-current snapshot**
of the last 100 spans, not a continuous real-time stream; full streaming remains unimplemented.
Reported durations are client telemetry and must not be mistaken for independently
server-measured agent timings. Agent registration and native instrumenting SDK remain required.

## Execution budgets
The default deterministic inspection budget is 20,000 microseconds per request.
Measured overrun rejects the content with `GUARDRAIL_EXECUTION_BUDGET_EXCEEDED`.
This post-execution measurement cannot preempt a blocking regex or guarantee a
hard wall-clock deadline. The standalone benchmark uses synthetic traffic and
requires p99 <=20ms in the CI runtime. Real hardware/traffic/SDK overhead,
end-to-end latency and host agent speed remain unqualified.

## Upstream drift
The weekly and on-demand `sdk-drift.yml` workflow compares npm lockfile
pinned versions and explicitly tracked Python compatibility baselines against
public package registries. It emits a report artifact, summary and tracked
GitHub issue on drift or registry failure. It does not upgrade dependencies.
Python baseline versions are **surveillance anchors, not assertions about
installed environments or verified compatibility**. An engineer must
evaluate actual dependency locks, supported version windows and integration
regressions before updating the baseline.

## Release gates
Use exact main/PR commit and run attempt, live tenant-separated PostgreSQL RLS,
mTLS agent enrollment, real-world guardrail latency and zero secret leakage
to qualify. A Vercel READY build only proves the build succeeded, not runtime
identity, backend access, live trace ingestion or endpoint protection.
