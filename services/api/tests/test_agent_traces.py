from datetime import datetime, timezone
from uuid import uuid4

from app.guardrails import inspect_with_budget


def test_agent_execution_metadata_is_tenant_scoped_and_idempotent(harness):
    client, auth, a, b = harness
    trace, span = str(uuid4()), str(uuid4())
    payload = {
        "trace_id": trace, "span_id": span, "agent_ref": "agent-01",
        "phase": "tool_review", "outcome": "denied", "elapsed_us": 620,
        "occurred_at": datetime.now(timezone.utc).isoformat()
    }
    path = "/v1/ai/agent-traces"
    assert client.post(path, json=payload, headers=auth("viewer-A")).status_code == 403
    r = client.post(path, json=payload, headers=auth("analyst-A"))
    assert r.status_code == 201, r.text
    assert client.post(path, json=payload, headers=auth("analyst-A")).status_code == 409
    assert client.get(path, headers=auth("viewer-A")).status_code == 403
    spans = client.get(path + "?trace_id=" + trace, headers=auth("analyst-A")).json()
    assert len(spans) == 1
    assert spans[0]["phase"] == "tool_review" and spans[0]["elapsed_us"] == 620
    assert client.get(path, headers=auth("owner-B", b)).json() == []
    assert client.post(path, json={**payload, "span_id": str(uuid4()), "raw_prompt": "secret"},
                       headers=auth("analyst-A")).status_code == 422
    assert client.post(path, json={**payload, "span_id": str(uuid4()), "parent_span_id": payload["span_id"]},
                       headers=auth("analyst-A")).status_code == 201


def test_budget_guards_block_on_overrun(monkeypatch):
    from app import guardrails
    times = iter((0, 50_000_000))
    monkeypatch.setattr("time.perf_counter_ns", lambda: next(times))
    decision, elapsed_us = guardrails.inspect_with_budget("benign request", max_us=20_000)
    assert decision.action == "Block"
    assert decision.reason_code == "GUARDRAIL_EXECUTION_BUDGET_EXCEEDED"
    assert elapsed_us == 50_000


def test_budget_normal_inspection(harness):
    client, auth, _, _ = harness
    data = client.post("/v1/ai/inspect", headers=auth(), json={"text": "Hello"}).json()
    assert data["decision"] == "Allow"
    assert data["guardrail_budget_us"] == 20000
    assert isinstance(data["guardrail_elapsed_us"], int)
