"""Readiness must not succeed for a reachable but unmigrated datastore."""
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.database import create_local_schema
from app.main import create_app


def test_readyz_requires_complete_schema(tmp_path):
    database_path = tmp_path / "readiness.db"
    engine = create_engine(
        f"sqlite:///{database_path}", connect_args={"check_same_thread": False}
    )
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        oidc_issuer="https://auth.onesa.eu/",
        oidc_audience="https://security-api.onesa.eu",
    )
    app = create_app(settings, sessionmaker(engine))
    try:
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            missing = client.get("/readyz")
            assert missing.status_code == 503
            assert "tenant-isolated schema unavailable" in missing.json()["detail"]

            create_local_schema(engine)
            ready = client.get("/readyz")
            assert ready.status_code == 200
            assert ready.json() == {"status": "ready"}

            with engine.begin() as connection:
                connection.exec_driver_sql("DROP TABLE audit_entries")
            assert client.get("/readyz").status_code == 503
            # Liveness must remain distinct from database readiness.
            assert client.get("/healthz").status_code == 200
    finally:
        engine.dispose()
