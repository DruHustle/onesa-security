import hashlib
from functools import lru_cache
import re
from dataclasses import dataclass
from datetime import datetime, timezone
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException
from sqlalchemy import select
from .models import Collector, Membership
from .database import tenant_context

TENANT_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2, "owner": 3}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    subject: str
    role: str


@lru_cache(maxsize=8)
def _jwks_client(uri: str):
    return PyJWKClient(uri, cache_jwk_set=True, lifespan=300, timeout=4)


def verify_access_token(token: str, settings) -> str:
    if len(token) > 8192:
        raise HTTPException(401, "Invalid access token")
    try:
        jwks_uri = settings.oidc_issuer.rstrip("/") + "/.well-known/jwks.json"
        signing_key = _jwks_client(jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, algorithms=["RS256"],
                            audience=settings.oidc_audience, issuer=settings.oidc_issuer,
                            options={"require": ["sub", "aud", "exp", "iat", "iss"]}, leeway=30)
        subject = claims["sub"]
        if not isinstance(subject, str) or len(subject) > 255 or not subject:
            raise ValueError("bad subject")
        return subject
    except Exception:
        raise HTTPException(401, "Invalid access token") from None


def authorize_member(session, subject: str, tenant_id: str) -> Principal:
    if not TENANT_RE.fullmatch(tenant_id):
        raise HTTPException(400, "Invalid organization identifier")
    tenant_context(session, tenant_id)
    membership = session.get(Membership, (tenant_id, subject))
    if membership is None or membership.role not in ROLE_RANK:
        raise HTTPException(403, "Organization access denied")
    return Principal(tenant_id, subject, membership.role)


def require_role(principal: Principal, minimum: str):
    if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
        raise HTTPException(403, "Insufficient organization role")


def authorize_collector(session, token: str, require_mtls: bool, mtls_verified: bool) -> Collector:
    if require_mtls and not mtls_verified:
        raise HTTPException(403, "Collector mutual TLS verification required")
    # Self-identifying high-entropy scoped credential; never use an unauthenticated
    # global tenant-wide credential scan to avoid RLS bypass.
    if len(token) < 75 or len(token) > 300 or "." not in token:
        raise HTTPException(401, "Invalid collector credential")
    tenant_id, _ = token.split(".", 1)
    if not TENANT_RE.fullmatch(tenant_id):
        raise HTTPException(401, "Invalid collector credential")
    tenant_context(session, tenant_id)
    digest = hashlib.sha256(token.encode()).hexdigest()
    collector = session.scalar(select(Collector).where(Collector.tenant_id == tenant_id,
        Collector.token_digest == digest, Collector.revoked.is_(False)))
    exp = collector.expires_at if collector else None
    if not exp or exp.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise HTTPException(401, "Invalid collector credential")
    return collector
