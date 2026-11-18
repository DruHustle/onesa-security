from dataclasses import dataclass
from os import environ
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    database_url: str
    oidc_issuer: str
    oidc_audience: str
    upstream_url: str | None = None
    upstream_key: str | None = None
    upstream_model: str | None = None
    collector_mtls_required: bool = True

    @classmethod
    def from_env(cls):
        issuer = environ.get("OIDC_ISSUER", "https://auth.onesa.eu/")
        audience = environ.get("OIDC_AUDIENCE", "https://security-api.onesa.eu")
        parts = urlsplit(issuer)
        if (parts.scheme != "https" or not parts.netloc or parts.username or parts.password
                or parts.query or parts.fragment or parts.path not in ("", "/")):
            raise RuntimeError("OIDC_ISSUER must be a trusted HTTPS issuer origin")
        upstream = environ.get("AI_UPSTREAM_URL") or None
        if upstream:
            u = urlsplit(upstream)
            if (u.scheme != "https" or not u.hostname or u.username or u.password or u.query
                    or u.fragment or u.path != "/v1/chat/completions"):
                raise RuntimeError("AI_UPSTREAM_URL must be a fixed HTTPS /v1/chat/completions endpoint")
        return cls(
            database_url=environ.get("DATABASE_URL", ""),
            oidc_issuer=issuer if issuer.endswith("/") else issuer + "/",
            oidc_audience=audience,
            upstream_url=upstream,
            upstream_key=environ.get("AI_UPSTREAM_API_KEY") or None,
            upstream_model=environ.get("AI_UPSTREAM_MODEL") or None,
            collector_mtls_required=environ.get("COLLECTOR_REQUIRE_MTLS", "true").lower() != "false",
        )
