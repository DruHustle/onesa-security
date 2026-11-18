"""Provision an *ephemeral loopback-only test database* for PostgreSQL RLS verification.

Never invoke against an existing user database or an external server.
"""
import os
from pathlib import Path
from urllib.parse import urlsplit
import psycopg


def main():
    root = Path(__file__).resolve().parents[1]
    dsn = os.environ.get("ONESA_RLS_TEST_ADMIN_URL", "")
    url = urlsplit(dsn)
    if (url.scheme not in {"postgres", "postgresql"} or url.hostname not in {"localhost", "127.0.0.1"}
            or not url.path.endswith("_test") or not os.environ.get("CI")):
        raise SystemExit("Refusing database setup outside explicit ephemeral CI loopback test database")
    with psycopg.connect(dsn, autocommit=True) as db:
        with db.cursor() as cur:
            # Deterministic local integration fixture; not a production service account.
            cur.execute("CREATE ROLE onesa_api LOGIN PASSWORD 'ci-local-rls-user' NOINHERIT NOBYPASSRLS")
            for path in ("001_initial.sql", "002_findings_and_approvals.sql"):
                cur.execute((root / "migrations" / path).read_text())
            cur.execute("GRANT CONNECT ON DATABASE onesa_security_test TO onesa_api")
            cur.execute("GRANT USAGE ON SCHEMA public TO onesa_api")
            cur.execute("GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO onesa_api")
            cur.execute("REVOKE UPDATE ON audit_entries FROM onesa_api")
            # Prove RLS against populated records, not only an empty database.
            # These deterministic fixture IDs are confined to the disposable CI DB.
            tenants = (
                ("11111111-1111-4111-8111-111111111111", "Synthetic tenant A", "synthetic-a"),
                ("22222222-2222-4222-8222-222222222222", "Synthetic tenant B", "synthetic-b"),
            )
            cur.executemany(
                "INSERT INTO organizations (id, name, created_at) VALUES (%s, %s, now())",
                [(tenant, label) for tenant, label, _ in tenants],
            )
            cur.executemany(
                "INSERT INTO memberships (tenant_id, subject, role) VALUES (%s, %s, 'viewer')",
                [(tenant, subject) for tenant, _, subject in tenants],
            )
    print("Ephemeral PostgreSQL migrations applied with separated NOBYPASSRLS runtime role")


if __name__ == "__main__":
    main()
