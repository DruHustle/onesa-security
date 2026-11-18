# Developer runbook

## Prerequisites

Docker Engine/Compose, Python 3.11+ for offline API tests, and Node 24.12+ for Next.js. Obtain a **dedicated development** confidential application at existing Onesa Auth0 with registered callback `http://localhost:3000/auth/callback`, API audience `https://security-api.onesa.eu` or a separately registered staging audience, and a tested member `sub`. Do not copy any production client secret into Git or public CI.

## Offline API tests

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e './services/api[test]'
(cd services/api && pytest -q)
(cd agents/linux && python -m unittest -q test_collector.py)
```

## Isolated local stack

Set `DEV_DB_ADMIN_PASSWORD`, `DEV_APP_DB_PASSWORD` (URL-safe non-production values), `ONESA_ORGANIZATION_ID` (UUID), `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` and `AUTH0_SECRET` in your *local shell or private environment*. Do not create a checked-in `.env`.

```sh
docker compose -f compose.dev.yaml up -d --build
# Compose sets ONESA_SECURITY_ENV=development and ONESA_DEV_ISOLATED=1
# only for this loopback development API. Outside this explicit context,
# COLLECTOR_REQUIRE_MTLS=false is rejected at startup.
# Create only the approved initial organization and actual owner subject:
docker compose -f compose.dev.yaml exec api python -m app.bootstrap \
  --org-id "$ONESA_ORGANIZATION_ID" --org-name "Onesa UG" --owner-sub "$ONESA_OWNER_SUB"
```

Browse `http://localhost:3000` and sign in with the registered Onesa Auth0 development client. The BFF obtains an audience-specific token; the API checks the verified subject's membership in the chosen tenant. On mismatch, access is denied. `GET http://127.0.0.1:8080/healthz` reports only service liveness, not deployed security effectiveness. Collector ingestion in this Compose is deliberately limited to developer preview with `COLLECTOR_REQUIRE_MTLS=false`; **do not publish port 8080 beyond loopback**.

## Operational caution

Never run `docker compose down -v` against a non-disposable database; it destroys volumes. Perform staging Postgres RLS, identity, mTLS and browser checks with approved private credentials before considering deployment. The web dependency lockfile is committed, and the source build runs in CI. This does not qualify the deployed site; verify browser authentication, backend access and collected data against the exact deployed revision. Docker network egress is needed to install dependencies and contact the dedicated OIDC provider.
