# Onesa Security Python agent execution tracer (developer preview)

This SDK is opt-in metadata instrumentation for approved AI agents, not an
OS-wide collector, a prompt-injection firewall or a model tool executor.

Wrap the desired agent execution phase with `with tracer.span(agent_ref="my-agent",phase="inference"):`.
The context manager returns a span identifier and trace identifier for linking
nested phases. It records phase, outcome and measured elapsed time only.

Production requires:
- Approved, revocable collector credential provisioned by an organization admin
- TLS endpoint ending with `/v1/collector/ai/agent-traces`, client certificate and
  private key, pinned trust chain (system CA or explicit CA bundle)
- Onesa Security API ingress that independently validates client mTLS and
  sets the ASGI scope verified bit from *trusted ingress*, not a browser header
- Verified tenant permissions and storage RLS

The internal queue is bounded (default 128); telemetry drops on saturation or
network failure rather than blocking host agent execution. `flush()` is for
graceful worker shutdown, not the inference hot path.

Do not pass prompts, API keys, tool arguments or personal data to the tracer.
It reports process-issued timings; use separately measured host-agent p95/p99
and independent performance tests before production.
