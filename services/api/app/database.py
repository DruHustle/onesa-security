from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from .models import Base


def db_factory(url: str):
    if not url:
        raise RuntimeError("DATABASE_URL is required; no implicit production database")
    engine = create_engine(url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    return engine, sessionmaker(engine, expire_on_commit=False)


def tenant_context(session: Session, tenant_id: str):
    # PostgreSQL RLS enforces the same boundary independently of ORM filters.
    # Untrusted requested tenant IDs are not authorizations; membership is checked separately.
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT set_config('onesa.tenant_id', :id, true)"), {"id": tenant_id})


def create_local_schema(engine):
    # Tests and explicitly non-production local SQLite only. Postgres uses versioned migration.
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Postgres schema must be managed by migrations")
    Base.metadata.create_all(engine)
