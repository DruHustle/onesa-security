from datetime import datetime, timezone
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main as api
from app.config import Settings
from app.database import create_local_schema
from app.models import Membership, Organization


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    create_local_schema(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    org_a, org_b = str(uuid4()), str(uuid4())
    with session_factory.begin() as db:
        db.add_all([
            Organization(id=org_a, name="Onesa UG"),
            Organization(id=org_b, name="Independent tenant"),
            Membership(tenant_id=org_a, subject="owner-A", role="owner"),
            Membership(tenant_id=org_a, subject="viewer-A", role="viewer"),
            Membership(tenant_id=org_a, subject="analyst-A", role="analyst"),
            Membership(tenant_id=org_b, subject="owner-B", role="owner"),
        ])
    # In integration tests only, replace signed OIDC verification with known subjects;
    # all tenant membership and role checks are still executed against the real DB.
    monkeypatch.setattr(api, "verify_access_token", lambda token, cfg: token)
    settings = Settings(database_url=url, oidc_issuer="https://auth.onesa.eu/",
                        oidc_audience="https://security-api.onesa.eu", collector_mtls_required=False)
    client = TestClient(api.create_app(settings, session_factory))
    def auth(subject="owner-A", org=org_a):
        return {"Authorization": "Bearer " + subject, "X-Onesa-Organization": org}
    return client, auth, org_a, org_b


def event(external_id, event_type="auth.failure", subject="device-001"):
    return {"external_id": external_id, "event_type": event_type, "subject_ref": subject,
            "occurred_at": datetime.now(timezone.utc).isoformat()}
