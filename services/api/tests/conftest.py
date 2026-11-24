from datetime import datetime, timezone
from time import time
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main as api
from app.auth import VerifiedAccess
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
            Membership(tenant_id=org_a, subject="owner-A2", role="owner"),
            Membership(tenant_id=org_b, subject="owner-B", role="owner"),
        ])
    # Simulate verified identities here; tenant membership and MFA policy still
    # run through the real dependency and database.
    def verified_identity(token, _settings):
        subject, _, mfa_claim = token.partition(";")
        mfa_at = None if mfa_claim == "missing" else int(time()) - int(mfa_claim or 0)
        return VerifiedAccess(subject, mfa_at)
    monkeypatch.setattr(api, "verify_access_token", verified_identity)
    settings = Settings(database_url=url, oidc_issuer="https://auth.onesa.eu/",
                        oidc_audience="https://security-api.onesa.eu", collector_mtls_required=False)
    client = TestClient(api.create_app(settings, session_factory))
    def auth(subject="owner-A", org=org_a, *, mfa_age=0):
        mfa_claim = "missing" if mfa_age is None else str(mfa_age)
        return {"Authorization": "Bearer " + subject + ";" + mfa_claim, "X-Onesa-Organization": org}
    return client, auth, org_a, org_b


def event(external_id, event_type="auth.failure", subject="device-001"):
    return {"external_id": external_id, "event_type": event_type, "subject_ref": subject,
            "occurred_at": datetime.now(timezone.utc).isoformat()}
