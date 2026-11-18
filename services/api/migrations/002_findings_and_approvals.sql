-- Onesa Security 002: evidence-backed findings and human-reviewed remediation proposals.
-- Apply with migration principal AFTER 001. Runtime role must remain NOBYPASSRLS.
BEGIN;
CREATE TABLE findings (
  id VARCHAR(36) PRIMARY KEY,
  tenant_id VARCHAR(36) NOT NULL,
  collector_id VARCHAR(36) NOT NULL,
  external_id VARCHAR(120) NOT NULL,
  asset_ref VARCHAR(150) NOT NULL,
  title VARCHAR(150) NOT NULL,
  category VARCHAR(30) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  cve_id VARCHAR(24),
  evidence_ref VARCHAR(120) NOT NULL,
  status VARCHAR(20) NOT NULL,
  resolution_note VARCHAR(300),
  verified_by VARCHAR(255),
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (tenant_id, collector_id) REFERENCES collectors(tenant_id, id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, collector_id, external_id)
);
CREATE INDEX finding_queue ON findings (tenant_id, status, severity, last_seen);
CREATE TABLE remediation_proposals (
  id VARCHAR(36) PRIMARY KEY,
  tenant_id VARCHAR(36) NOT NULL,
  finding_id VARCHAR(36) NOT NULL,
  action_type VARCHAR(30) NOT NULL,
  action_summary VARCHAR(500) NOT NULL,
  impact_summary VARCHAR(500) NOT NULL,
  rollback_plan VARCHAR(500) NOT NULL,
  requested_by VARCHAR(255) NOT NULL,
  approved_by VARCHAR(255),
  decision_note VARCHAR(300),
  status VARCHAR(20) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ,
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, id)
);
CREATE INDEX remediation_queue ON remediation_proposals (tenant_id, status, created_at);
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON findings USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));
ALTER TABLE remediation_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON remediation_proposals USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));
-- Runtime cannot DROP or ALTER schema; grants are explicit. Execute migration as schema owner.
GRANT SELECT, INSERT, UPDATE ON findings, remediation_proposals TO onesa_api;
COMMIT;
