"""Catch drift between the versioned database migrations and local/Oracle manifests.

These are configuration contract tests, not a substitute for actually starting
PostgreSQL, applying migrations and testing the restricted runtime role.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def migration_names():
    names = sorted(p.name for p in (ROOT / "services/api/migrations").glob("[0-9][0-9][0-9]_*.sql"))
    assert names, "No versioned migrations in repository"
    return names


def test_dev_compose_mounts_every_migration_and_installs_in_order():
    compose = (ROOT / "compose.dev.yaml").read_text()
    init = (ROOT / "infra/initdb/01-install.sh").read_text()
    names = migration_names()
    invoked = re.findall(r"-f /schema/([0-9]{3}_[A-Za-z0-9_]+[.]sql)", init)
    assert invoked == names, ("Fresh PostgreSQL setup must apply every migration once in order", names, invoked)
    for name in names:
        assert f"./services/api/migrations/{name}:/schema/{name}:ro" in compose, name
    assert '"127.0.0.1:8080:8080"' in compose, "Development API must be loopback-only"
    assert '"127.0.0.1:3000:3000"' in compose, "Development web must be loopback-only"
    assert "ONESA_DEV_ISOLATED: \"1\"" in compose
    assert 'COLLECTOR_REQUIRE_MTLS: "false"' in compose, "Explicit, isolated development exception only"


def test_oracle_api_template_is_private_and_fails_closed():
    text = (ROOT / "deploy/compose.oracle.yaml").read_text()
    assert "127.0.0.1:" in text
    assert "COLLECTOR_REQUIRE_MTLS: \"true\"" in text
    assert "read_only: true" in text
    assert "no-new-privileges:true" in text
    assert "cap_drop:" in text
    assert "healthcheck:" in text
    assert "/readyz" in text
    assert "/etc/onesa/security/api.env" in text
