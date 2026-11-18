from datetime import datetime, timezone
from uuid import uuid4


def event():
    return {"trace_id":str(uuid4()), "span_id":str(uuid4()), "agent_ref":"ai-agent-001",
            "phase":"tool_review", "outcome":"denied", "elapsed_us":420,
            "occurred_at":datetime.now(timezone.utc).isoformat()}


def test_authorized_collector_trace_ingestion_is_tenant_scoped(harness):
    client, auth, tenant_a, tenant_b = harness
    enrol = client.post("/v1/collectors", headers=auth(), json={"name":"Agent telemetry"})
    assert enrol.status_code == 200
    credential = enrol.json()["credential"]
    payload = event()
    url = "/v1/collector/ai/agent-traces"
    assert client.post(url, json=payload, headers=auth()).status_code == 401
    collector={"Authorization":"Collector "+credential}
    added = client.post(url, headers=collector, json=payload)
    assert added.status_code == 201, added.text
    assert added.json()["span_id"] == payload["span_id"]
    assert client.post(url, headers=collector, json=payload).status_code == 409
    spans = client.get("/v1/ai/agent-traces", headers=auth("analyst-A")).json()
    assert [s["span_id"] for s in spans] == [payload["span_id"]]
    assert client.get("/v1/ai/agent-traces", headers=auth("owner-B",tenant_b)).json() == []
    invalid = {**payload, "span_id":str(uuid4()), "parent_span_id":payload["span_id"],
               "raw_prompt":"should never be stored"}
    assert client.post(url, headers=collector, json=invalid).status_code == 422
    revoke=client.post(f"/v1/collectors/{enrol.json()['collector_id']}/revoke",headers=auth())
    assert revoke.status_code == 200
    assert client.post(url, headers=collector, json={**payload,"span_id":str(uuid4())}).status_code == 401


def test_machine_ingress_rejects_unverified_client_certificate(tmp_path):
    from app.main import create_app
    from app.config import Settings
    from app.database import create_local_schema
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from fastapi.testclient import TestClient
    engine=create_engine(f"sqlite:///{tmp_path / 'mtls-agent.db'}",connect_args={"check_same_thread":False})
    create_local_schema(engine)
    settings=Settings(database_url="sqlite:///unused",oidc_issuer="https://auth.onesa.eu/",
                      oidc_audience="https://security-api.onesa.eu")
    app=create_app(settings,sessionmaker(engine))
    r=TestClient(app).post("/v1/collector/ai/agent-traces",
        headers={"Authorization":"Collector "+"a"*100},json=event())
    assert r.status_code == 403
