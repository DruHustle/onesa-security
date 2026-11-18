-- Trace metadata only. Apply after 002 as migration owner; runtime cannot bypass RLS.
BEGIN;
CREATE TABLE ai_agent_spans (
  id VARCHAR(36) PRIMARY KEY,
  tenant_id VARCHAR(36) NOT NULL REFERENCES organizations(id),
  trace_id VARCHAR(36) NOT NULL,
  span_id VARCHAR(36) NOT NULL,
  parent_span_id VARCHAR(36),
  agent_ref VARCHAR(120) NOT NULL,
  phase VARCHAR(25) NOT NULL,
  outcome VARCHAR(20) NOT NULL,
  elapsed_us INTEGER NOT NULL CHECK (elapsed_us BETWEEN 0 AND 60000000),
  occurred_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  UNIQUE (tenant_id, agent_ref, span_id)
);
CREATE INDEX ai_agent_trace_lookup ON ai_agent_spans(tenant_id, trace_id, occurred_at);
ALTER TABLE ai_agent_spans ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_spans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON ai_agent_spans
  USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));
GRANT SELECT, INSERT ON ai_agent_spans TO onesa_api;
COMMIT;
