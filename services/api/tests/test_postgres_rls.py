"""Real PostgreSQL boundary qualification. Intentionally skipped without isolated test DSNs.

Requires migration-owner test DB and separate NOBYPASSRLS role. Never run against
production or staging. CI uses its own disposable postgres container.
"""
import os
from pathlib import Path
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from app.database import tenant_context
from app.models import Organization, Membership, Collector, Finding


@pytest.mark.skipif(not os.environ.get("ONESA_RLS_TEST_APP_URL"), reason="isolated PostgreSQL RLS DSN not provided")
def test_postgres_real_force_rls():
    url = os.environ["ONESA_RLS_TEST_APP_URL"]
    assert url.startswith("postgresql+") and "_test" in url, "Refuse non-test databases"
    engine = create_engine(url)
    tenant_a = "11111111-1111-4111-8111-111111111111"
    tenant_b = "22222222-2222-4222-8222-222222222222"
    try:
        with Session(engine) as db:
            role = db.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
            assert role == (False, False), "Application role may not bypass RLS"
            tables = ["organizations", "memberships", "collectors", "assets", "security_events",
                      "alerts", "guardrail_policies", "audit_entries", "findings", "remediation_proposals"]
            for table in tables:
                enabled = db.execute(text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname=:table"), {"table": table}).one()
                assert enabled == (True, True), f"RLS missing for {table}"
            # The migration-owner CI fixture seeded two tenants. Without
            # context, even real rows must be completely invisible.
            assert db.execute(text("SELECT id FROM organizations")).scalars().all() == []
            assert db.execute(text("SELECT subject FROM memberships")).scalars().all() == []

            tenant_context(db, tenant_a)
            assert db.execute(text("SELECT id FROM organizations")).scalars().all() == [tenant_a]
            assert db.execute(text("SELECT subject FROM memberships")).scalars().all() == ["synthetic-a"]
            assert db.execute(text("SELECT id FROM organizations WHERE id=:id"), {"id": tenant_b}).first() is None
            assert db.execute(text("SELECT subject FROM memberships WHERE tenant_id=:id"), {"id": tenant_b}).first() is None

            # RLS must block creating a THIRD tenant, not merely trigger a
            # duplicate-key error from inserting an existing fixture ID.
            from sqlalchemy.exc import DBAPIError
            forbidden = str(uuid4())
            with pytest.raises(DBAPIError):
                db.execute(
                    text("INSERT INTO organizations (id,name,created_at) VALUES (:id,'cross-tenant', now())"),
                    {"id": forbidden},
                )
            db.rollback()

            tenant_context(db, tenant_b)
            assert db.execute(text("SELECT id FROM organizations")).scalars().all() == [tenant_b]
            assert db.execute(text("SELECT subject FROM memberships")).scalars().all() == ["synthetic-b"]
            assert db.execute(text("SELECT id FROM organizations WHERE id=:id"), {"id": tenant_a}).first() is None
            db.rollback()
    finally:
        engine.dispose()
