from datetime import timedelta, timezone
from sqlalchemy import select
from .models import Alert, Event


def evaluate_event(session, event: Event) -> Alert | None:
    if event.event_type in ("iam.privilege_change", "endpoint.persistence"):
        rule = "ONESA-PRIV-001" if event.event_type == "iam.privilege_change" else "ONESA-PERSIST-001"
        severity = "high"
        reason = "A monitored privilege change was reported" if rule == "ONESA-PRIV-001" else "An endpoint persistence event was reported"
        events = [event.id]
    elif event.event_type == "auth.failure":
        rule = "ONESA-AUTH-003"
        severity = "medium"
        start = event.occurred_at - timedelta(minutes=5)
        # No event-type inference from raw untrusted logs; only normalized collector records.
        recent = session.scalars(select(Event).where(
            Event.tenant_id == event.tenant_id, Event.subject_ref == event.subject_ref,
            Event.event_type == "auth.failure", Event.occurred_at >= start,
            Event.occurred_at <= event.occurred_at,
        ).order_by(Event.occurred_at.desc()).limit(3)).all()
        if len(recent) < 3:
            return None
        reason = "At least 3 failed sign-in events for the same subject within 5 minutes"
        events = [item.id for item in recent]
    else:
        return None
    existing = session.scalar(select(Alert).where(
        Alert.tenant_id == event.tenant_id, Alert.rule_id == rule,
        Alert.subject_ref == event.subject_ref, Alert.status != "closed",
    ))
    if existing:
        existing.event_ids = list(dict.fromkeys([*existing.event_ids, *events]))[-30:]
        return existing
    alert = Alert(tenant_id=event.tenant_id, rule_id=rule,
                  title={"ONESA-PRIV-001": "Privilege change reported", "ONESA-PERSIST-001": "Persistence activity reported",
                         "ONESA-AUTH-003": "Repeated authentication failures"}[rule],
                  severity=severity, subject_ref=event.subject_ref,
                  explanation=reason + "; investigate source telemetry before confirming compromise.", event_ids=events)
    session.add(alert)
    session.flush()
    return alert
