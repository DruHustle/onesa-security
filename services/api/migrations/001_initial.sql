-- Initial PostgreSQL schema for Onesa Security. Apply only with reviewed migration credentials.

-- Application role must be NO BYPASSRLS and distinct from migration owner.

BEGIN;

CREATE TABLE organizations (
	id VARCHAR(36) NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE alerts (
	id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(36) NOT NULL, 
	rule_id VARCHAR(80) NOT NULL, 
	title VARCHAR(150) NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	subject_ref VARCHAR(120) NOT NULL, 
	explanation VARCHAR(500) NOT NULL, 
	event_ids JSON NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	assigned_to VARCHAR(255), 
	disposition VARCHAR(300), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(tenant_id) REFERENCES organizations (id)
);

CREATE TABLE audit_entries (
	id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(36) NOT NULL, 
	actor_ref VARCHAR(255) NOT NULL, 
	action VARCHAR(70) NOT NULL, 
	target_ref VARCHAR(150) NOT NULL, 
	occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(tenant_id) REFERENCES organizations (id)
);

CREATE TABLE collectors (
	id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(36) NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	token_digest VARCHAR(64) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(tenant_id) REFERENCES organizations (id), 
	UNIQUE (tenant_id, id), 
	UNIQUE (token_digest)
);

CREATE TABLE guardrail_policies (
	tenant_id VARCHAR(36) NOT NULL, 
	version INTEGER NOT NULL, 
	block_injection BOOLEAN NOT NULL, 
	redact_pii BOOLEAN NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (tenant_id), 
	FOREIGN KEY(tenant_id) REFERENCES organizations (id)
);

CREATE TABLE memberships (
	tenant_id VARCHAR(36) NOT NULL, 
	subject VARCHAR(255) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	PRIMARY KEY (tenant_id, subject), 
	FOREIGN KEY(tenant_id) REFERENCES organizations (id)
);

CREATE TABLE assets (
	id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(36) NOT NULL, 
	collector_id VARCHAR(36) NOT NULL, 
	external_ref VARCHAR(150) NOT NULL, 
	category VARCHAR(30) NOT NULL, 
	label VARCHAR(150) NOT NULL, 
	os_family VARCHAR(30), 
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (tenant_id, collector_id, external_ref), 
	FOREIGN KEY(tenant_id, collector_id) REFERENCES collectors (tenant_id, id)
);

CREATE TABLE security_events (
	id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(36) NOT NULL, 
	collector_id VARCHAR(36) NOT NULL, 
	external_id VARCHAR(120) NOT NULL, 
	event_type VARCHAR(50) NOT NULL, 
	subject_ref VARCHAR(120) NOT NULL, 
	asset_ref VARCHAR(150), 
	occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	received_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (tenant_id, collector_id, external_id), 
	FOREIGN KEY(tenant_id, collector_id) REFERENCES collectors (tenant_id, id)
);

CREATE INDEX alert_queue ON alerts (tenant_id, status, created_at);

CREATE INDEX event_lookup ON security_events (tenant_id, subject_ref, event_type, occurred_at);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON organizations USING (id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

ALTER TABLE alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON alerts USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit_entries FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON audit_entries USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE collectors ENABLE ROW LEVEL SECURITY;

ALTER TABLE collectors FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON collectors USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE guardrail_policies ENABLE ROW LEVEL SECURITY;

ALTER TABLE guardrail_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON guardrail_policies USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;

ALTER TABLE memberships FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON memberships USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;

ALTER TABLE assets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON assets USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE security_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_boundary ON security_events USING (tenant_id = nullif(current_setting('onesa.tenant_id', true), '')) WITH CHECK (tenant_id = nullif(current_setting('onesa.tenant_id', true), ''));

COMMIT;

-- Default deny: no tenant context yields zero rows. The API sets SET LOCAL context per transaction.

-- Never connect the application as superuser or a BYPASSRLS role.

-- Separate migration/bootstrap privileges from normal application runtime privileges.
