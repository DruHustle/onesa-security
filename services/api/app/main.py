import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Principal, authorize_collector, authorize_member, require_role, verify_access_token
from .config import Settings
from .database import db_factory
from .detection import evaluate_event
from .guardrails import inspect_text, sanitize_model_output
from .models import Alert, Asset, AuditEntry, Collector, Event, GuardrailPolicy, now
from .schemas import AlertChange, AssetInput, ChatRequest, CollectorRegistration, EventInput, InspectRequest, PolicyUpdate


def create_app(settings: Settings | None = None, session_factory=None) -> FastAPI:
    cfg = settings or Settings.from_env()
    if session_factory is None:
        _, session_factory = db_factory(cfg.database_url)
    app = FastAPI(title="Onesa Security API", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.settings = cfg

    def get_db():
        with session_factory() as db:
            try:
                yield db
            finally:
                db.rollback()

    def current_principal(authorization: str | None = Header(None),
                          x_onesa_organization: str | None = Header(None), db: Session = Depends(get_db)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer access token required")
        if not x_onesa_organization:
            raise HTTPException(400, "Organization header required")
        subject = verify_access_token(authorization[7:], cfg)
        return authorize_member(db, subject, x_onesa_organization)

    def collector_principal(request: Request, authorization: str | None = Header(None), db: Session = Depends(get_db)):
        if not authorization or not authorization.startswith("Collector "):
            raise HTTPException(401, "Collector credential required")
        # Only trusted TLS termination may set the ASGI scope extension. Never use caller-supplied headers.
        verified = request.scope.get("onesa.mtls_verified") is True
        return authorize_collector(db, authorization[10:], cfg.collector_mtls_required, verified)

    def audit(db, p: Principal, action: str, target: str):
        db.add(AuditEntry(tenant_id=p.tenant_id, actor_ref=p.subject, action=action, target_ref=target))

    def policy(db, tenant_id: str):
        existing = db.get(GuardrailPolicy, tenant_id)
        if existing:
            return existing.block_injection, existing.redact_pii, existing.version
        return True, True, 0

    @app.get("/healthz")
    def health():
        return {"status": "alive", "product": "Onesa Security", "scope": "functional-foundation"}

    @app.get("/readyz")
    def ready(db: Session = Depends(get_db)):
        from sqlalchemy import text
        try:
            db.execute(text("SELECT 1"))
            return {"status": "ready"}
        except Exception:
            raise HTTPException(503, "Database unavailable") from None

    @app.get("/v1/overview")
    def overview(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        def count(model):
            return db.scalar(select(func.count()).select_from(model).where(model.tenant_id == p.tenant_id))
        return {"organization_id": p.tenant_id, "role": p.role, "real_data": True,
                "assets": count(Asset), "events": count(Event), "alerts": count(Alert),
                "collectors": count(Collector), "source": "Authorized Onesa Security collectors only"}

    @app.get("/v1/assets")
    def assets(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        data = db.scalars(select(Asset).where(Asset.tenant_id == p.tenant_id)
                          .order_by(Asset.last_seen.desc()).limit(100)).all()
        return [{"id": a.id, "label": a.label, "category": a.category, "os_family": a.os_family,
                 "external_ref": a.external_ref, "last_seen": a.last_seen} for a in data]

    @app.get("/v1/events")
    def events(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        data = db.scalars(select(Event).where(Event.tenant_id == p.tenant_id)
                          .order_by(Event.received_at.desc()).limit(100)).all()
        return [{"id": e.id, "event_type": e.event_type, "subject_ref": e.subject_ref,
                 "occurred_at": e.occurred_at, "received_at": e.received_at} for e in data]

    @app.get("/v1/alerts")
    def alerts(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        data = db.scalars(select(Alert).where(Alert.tenant_id == p.tenant_id)
                          .order_by(Alert.created_at.desc()).limit(100)).all()
        return [{"id": a.id, "rule_id": a.rule_id, "title": a.title, "severity": a.severity,
                 "subject_ref": a.subject_ref, "explanation": a.explanation, "event_ids": a.event_ids,
                 "status": a.status, "assigned_to": a.assigned_to, "disposition": a.disposition,
                 "created_at": a.created_at} for a in data]

    @app.patch("/v1/alerts/{alert_id}")
    def change_alert(alert_id: UUID, payload: AlertChange, p: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
        require_role(p, "analyst")
        a = db.scalar(select(Alert).where(Alert.tenant_id == p.tenant_id, Alert.id == str(alert_id)))
        if not a:
            raise HTTPException(404, "Alert not found")
        if payload.status == "closed" and not payload.disposition:
            raise HTTPException(422, "Closing an alert requires a disposition")
        a.status, a.assigned_to, a.disposition = payload.status, payload.assigned_to, payload.disposition
        audit(db, p, "alert.status_changed", a.id)
        db.commit()
        return {"id": a.id, "status": a.status}

    @app.post("/v1/collectors")
    def add_collector(payload: CollectorRegistration, p: Principal = Depends(current_principal),
                      db: Session = Depends(get_db)):
        require_role(p, "admin")
        from uuid import uuid4
        random_secret = secrets.token_urlsafe(40)
        credential = p.tenant_id + "." + random_secret
        collector = Collector(id=str(uuid4()), tenant_id=p.tenant_id, name=payload.name,
                              token_digest=hashlib.sha256(credential.encode()).hexdigest(),
                              expires_at=now() + timedelta(days=7))
        db.add(collector)
        audit(db, p, "collector.created", collector.id)
        db.commit()
        return {"collector_id": collector.id, "credential": credential,
                "expires_at": collector.expires_at, "warning": "Secret is returned only once; install in a protected file. Production mTLS required."}

    @app.post("/v1/collectors/{collector_id}/revoke")
    def revoke_collector(collector_id: UUID, p: Principal = Depends(current_principal),
                         db: Session = Depends(get_db)):
        require_role(p, "admin")
        c = db.scalar(select(Collector).where(Collector.tenant_id == p.tenant_id, Collector.id == str(collector_id)))
        if not c:
            raise HTTPException(404, "Collector not found")
        c.revoked = True
        audit(db, p, "collector.revoked", c.id)
        db.commit()
        return {"revoked": True}

    @app.post("/v1/collector/assets")
    def ingest_asset(payload: AssetInput, c: Collector = Depends(collector_principal), db: Session = Depends(get_db)):
        item = db.scalar(select(Asset).where(Asset.tenant_id == c.tenant_id, Asset.collector_id == c.id,
                                              Asset.external_ref == payload.external_ref))
        if item is None:
            item = Asset(tenant_id=c.tenant_id, collector_id=c.id, external_ref=payload.external_ref,
                         category=payload.category, label=payload.label, os_family=payload.os_family)
            db.add(item)
        else:
            item.label, item.os_family, item.category, item.last_seen = payload.label, payload.os_family, payload.category, now()
        db.commit()
        return {"asset_id": item.id, "recorded": True}

    @app.post("/v1/collector/events")
    def ingest_event(payload: EventInput, c: Collector = Depends(collector_principal), db: Session = Depends(get_db)):
        occurred = payload.occurred_at
        if occurred.utcoffset() is None:
            raise HTTPException(422, "occurred_at must include an offset")
        occurred = occurred.astimezone(timezone.utc)
        if occurred > now() + timedelta(minutes=5):
            raise HTTPException(422, "Event timestamp is in the future")
        existing = db.scalar(select(Event).where(Event.tenant_id == c.tenant_id, Event.collector_id == c.id,
                                                 Event.external_id == payload.external_id))
        if existing:
            return {"event_id": existing.id, "created": False, "alert_id": None}
        event = Event(tenant_id=c.tenant_id, collector_id=c.id, external_id=payload.external_id,
                      event_type=payload.event_type, subject_ref=payload.subject_ref,
                      asset_ref=payload.asset_ref, occurred_at=occurred)
        db.add(event)
        db.flush()
        a = evaluate_event(db, event)
        db.commit()
        return {"event_id": event.id, "created": True, "alert_id": a.id if a else None}

    @app.get("/v1/ai/policy")
    def get_policy(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        block, redact, version = policy(db, p.tenant_id)
        return {"version": version, "block_injection": block, "redact_pii": redact,
                "description": "Baseline heuristic detection, not complete prompt-injection prevention"}

    @app.put("/v1/ai/policy")
    def set_policy(payload: PolicyUpdate, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        require_role(p, "admin")
        _, _, version = policy(db, p.tenant_id)
        if version != payload.expected_version:
            raise HTTPException(409, "Policy changed; reload and retry")
        if version == 0:
            db.add(GuardrailPolicy(tenant_id=p.tenant_id, version=1,
                                   block_injection=payload.block_injection, redact_pii=payload.redact_pii))
        else:
            result = db.execute(update(GuardrailPolicy).where(GuardrailPolicy.tenant_id == p.tenant_id,
                  GuardrailPolicy.version == version).values(version=version + 1,
                  block_injection=payload.block_injection, redact_pii=payload.redact_pii, updated_at=now()))
            if result.rowcount != 1:
                raise HTTPException(409, "Concurrent policy update")
        audit(db, p, "ai.policy_updated", str(version + 1))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Concurrent policy update") from None
        return {"version": version + 1}

    @app.post("/v1/ai/inspect")
    def inspect(payload: InspectRequest, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        block, redact, version = policy(db, p.tenant_id)
        result = inspect_text(payload.text, block_injection=block, redact_pii=redact,
                              action_type=payload.action_type)
        audit(db, p, "ai.inspected." + result.action.lower(), result.reason_code)
        db.commit()
        return {"decision": result.action, "reason_code": result.reason_code,
                "effective_text": result.effective_text, "policy_version": version}

    @app.post("/v1/ai/chat/completions")
    async def gateway(payload: ChatRequest, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        if payload.stream:
            raise HTTPException(422, "Streaming gateway not implemented")
        if not cfg.upstream_url or not cfg.upstream_key or not cfg.upstream_model:
            raise HTTPException(503, "Approved AI upstream not configured")
        block, redact, version = policy(db, p.tenant_id)
        messages = []
        for m in payload.messages:
            inspected = inspect_text(m.content, block_injection=block, redact_pii=redact)
            if inspected.action == "Block":
                audit(db, p, "ai.gateway_blocked", inspected.reason_code)
                db.commit()
                raise HTTPException(403, "AI request blocked by " + inspected.reason_code)
            messages.append({"role": m.role, "content": inspected.effective_text})
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False) as client:
                res = await client.post(cfg.upstream_url, headers={"Authorization": "Bearer " + cfg.upstream_key},
                                        json={"model": cfg.upstream_model, "messages": messages, "stream": False})
            res.raise_for_status()
            if len(res.content) > 1_000_000:
                raise ValueError("provider response too large")
            data = res.json()
            choices = data.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0].get("message", {}).get("content"), str):
                raise ValueError("unsupported provider response")
            if choices[0]["message"].get("tool_calls"):
                raise ValueError("tool calls disabled")
            output = sanitize_model_output(choices[0]["message"]["content"])
            if output.action == "Block":
                audit(db, p, "ai.output_blocked", output.reason_code)
                db.commit()
                raise HTTPException(403, "AI output blocked by policy")
            # Only return reviewed text. Do not return uninspected provider metadata/tool data.
            audit(db, p, "ai.gateway_completed", output.reason_code)
            db.commit()
            return {"model": cfg.upstream_model, "choices": [{"index": 0, "message": {"role": "assistant", "content": output.effective_text}}],
                    "guardrail": {"decision": output.action, "policy_version": version}}
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            # Never echo provider error bodies (may contain prompts or credentials).
            raise HTTPException(502, "AI provider unavailable or response rejected") from None

    @app.get("/v1/audit")
    def audit_log(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
        require_role(p, "analyst")
        data = db.scalars(select(AuditEntry).where(AuditEntry.tenant_id == p.tenant_id)
                          .order_by(AuditEntry.occurred_at.desc()).limit(100)).all()
        return [{"action": e.action, "target_ref": e.target_ref, "actor_ref": e.actor_ref,
                 "occurred_at": e.occurred_at} for e in data]

    return app


# ASGI deployment entry point. No schema creation or demo seeding at startup.
# In tests create_app(settings, session_factory) uses isolated storage.
try:
    app = create_app()
except RuntimeError:
    # Import remains usable for tests. Production ASGI fails readiness if not configured.
    app = FastAPI(docs_url=None)
    @app.get("/healthz")
    def setup_required():
        return JSONResponse({"status": "not_configured"}, status_code=503)
