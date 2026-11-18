from dataclasses import dataclass
import ipaddress
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
            allowed_hosts = {v.strip().lower() for v in environ.get("AI_UPSTREAM_ALLOWED_HOSTS", "").split(",") if v.strip()}
            if (u.scheme != "https" or not u.hostname or u.username or u.password or u.query
                    or u.fragment or u.path != "/v1/chat/completions" or u.port not in (None, 443)
                    or u.hostname.lower() not in allowed_hosts or u.hostname.lower() == "localhost"
                    or u.hostname.lower().endswith((".local", ".internal"))):
                raise RuntimeError("AI upstream must be a reviewed HTTPS provider host in AI_UPSTREAM_ALLOWED_HOSTS")
            try:
                ipaddress.ip_address(u.hostname)
                raise RuntimeError("IP-literal AI upstreams are refused; use reviewed provider hostnames")
            except ValueError:
                pass
        mtls_value = environ.get("COLLECTOR_REQUIRE_MTLS", "true").strip().lower()
        if mtls_value not in {"true", "false"}:
            raise RuntimeError("COLLECTOR_REQUIRE_MTLS must be true or false")
        if mtls_value == "false" and not (
            environ.get("ONESA_SECURITY_ENV") == "development"
            and environ.get("ONESA_DEV_ISOLATED") == "1"
        ):
            # A mistyped or inherited public deployment configuration must
            # never silently disable the independent collector certificate gate.
            raise RuntimeError("Collector mTLS can only be disabled for explicitly isolated development")
        return cls(
            database_url=environ.get("DATABASE_URL", ""),
            oidc_issuer=issuer if issuer.endswith("/") else issuer + "/",
            oidc_audience=audience,
            upstream_url=upstream,
            upstream_key=environ.get("AI_UPSTREAM_API_KEY") or None,
            upstream_model=environ.get("AI_UPSTREAM_MODEL") or None,
            collector_mtls_required=mtls_value == "true",
        )
