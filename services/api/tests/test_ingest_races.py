"""Deterministic regression for simultaneous collector replay races.

Simulate a competing transaction inserting the same unique key between a
request's initial lookup and INSERT. The database's real unique constraint
must be handled without rolling back the tenant-scoped parent transaction.
"""
from sqlalchemy.orm import Session
from conftest import event


def competing_insert(monkeypatch, table, request):
    original = Session.scalar
    hidden = 0

    def hide_first_lookup(session, statement, *args, **kwargs):
        nonlocal hidden
        if hidden == 0 and f"FROM {table}" in str(statement):
            hidden += 1
            return None
        return original(session, statement, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Session, "scalar", hide_first_lookup)
        response = request()
    assert hidden == 1, f"Expected one simulated {table} SELECT/INSERT race"
    return response


def enrolled_collector(client, auth):
    response = client.post("/v1/collectors", headers=auth(), json={"name": "race probe"})
    assert response.status_code == 200
    return {"Authorization": "Collector " + response.json()["credential"]}


def test_asset_replay_tolerates_competing_insert(harness, monkeypatch):
    client, auth, _, _ = harness
    collector = enrolled_collector(client, auth)
    record = {"external_ref": "replay-host-01", "category": "endpoint",
              "label": "Initial host", "os_family": "linux"}
    first = client.post("/v1/collector/assets", headers=collector, json=record)
    assert first.status_code == 200, first.text
    replay = competing_insert(monkeypatch, "assets",
        lambda: client.post("/v1/collector/assets", headers=collector,
                            json={**record, "label": "Updated host"}))
    assert replay.status_code == 200, replay.text
    assert replay.json()["asset_id"] == first.json()["asset_id"]
    rows = client.get("/v1/assets", headers=auth()).json()
    assert len(rows) == 1 and rows[0]["label"] == "Updated host"


def test_security_event_replay_tolerates_competing_insert_without_duplicate_alert(harness, monkeypatch):
    client, auth, _, _ = harness
    collector = enrolled_collector(client, auth)
    record = event("replay-event-0001", "endpoint.persistence")
    first = client.post("/v1/collector/events", headers=collector, json=record)
    assert first.status_code == 200 and first.json()["created"], first.text
    replay = competing_insert(monkeypatch, "security_events",
        lambda: client.post("/v1/collector/events", headers=collector, json=record))
    assert replay.status_code == 200, replay.text
    assert replay.json() == {"event_id": first.json()["event_id"],
                             "created": False, "alert_id": None}
    assert len(client.get("/v1/events", headers=auth()).json()) == 1
    assert len(client.get("/v1/alerts", headers=auth()).json()) == 1


def test_finding_replay_tolerates_competing_insert_and_reopens_reviewed_record(harness, monkeypatch):
    client, auth, _, _ = harness
    collector = enrolled_collector(client, auth)
    asset = {"external_ref": "finding-host-01", "category": "server",
             "label": "Finding host", "os_family": "linux"}
    assert client.post("/v1/collector/assets", headers=collector, json=asset).status_code == 200
    report = {"external_id": "finding-replay-001", "asset_ref": asset["external_ref"],
              "title": "SSH configuration review", "category": "configuration",
              "severity": "medium", "evidence_ref": "observed-ssh-0001"}
    first = client.post("/v1/collector/findings", headers=collector, json=report)
    assert first.status_code == 200 and first.json()["created"], first.text
    finding_id = first.json()["id"]
    verified = client.post(f"/v1/findings/{finding_id}/resolve", headers=auth("analyst-A"),
        json={"verification": "false_positive", "evidence_ref": "reviewed-ssh-0001",
              "note": "Test fixture found no exposure during manual verification"})
    assert verified.status_code == 200, verified.text
    replay = competing_insert(monkeypatch, "findings",
        lambda: client.post("/v1/collector/findings", headers=collector,
                            json={**report, "evidence_ref": "observed-ssh-0002"}))
    assert replay.status_code == 200, replay.text
    assert replay.json()["created"] is False and replay.json()["id"] == finding_id
    rows = client.get("/v1/findings", headers=auth()).json()
    assert len(rows) == 1 and rows[0]["status"] == "reported"
    assert rows[0]["evidence_ref"] == "observed-ssh-0002"
    assert rows[0]["verified_by"] is None
