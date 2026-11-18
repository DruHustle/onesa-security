#!/usr/bin/env bash
# Exact CI-only PostgreSQL Docker runtime smoke. Never point at staging/customer DB.
set -euo pipefail
: "${ONESA_RLS_TEST_APP_URL:?Isolated CI PostgreSQL URL required}"
case "${ONESA_RLS_TEST_APP_URL}" in
  postgresql+psycopg://onesa_api:*@127.0.0.1:5432/onesa_security_test) ;;
  *) echo "Refusing non-local or non-test Postgres connection" >&2; exit 2 ;;
esac
cid="onesa-security-ci-api"
cleanup() { docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run --detach --name "$cid" --network host --user 10001:10001 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL --pids-limit 64 --security-opt no-new-privileges \
  --env DATABASE_URL="$ONESA_RLS_TEST_APP_URL" \
  --env OIDC_ISSUER=https://auth.onesa.eu/ \
  --env OIDC_AUDIENCE=https://security-api.onesa.eu \
  --env COLLECTOR_REQUIRE_MTLS=true \
  onesa-security-api:ci >/dev/null
ready=0
for attempt in $(seq 1 40); do
  if curl --fail --silent --show-error --max-time 2 \
       http://127.0.0.1:8080/readyz >/tmp/onesa-api-ready-response.json 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then
  echo "API container failed migrated non-bypass PostgreSQL readiness" >&2
  exit 1
fi
python - <<'PY'
import json
from pathlib import Path
payload=json.loads(Path("/tmp/onesa-api-ready-response.json").read_text())
assert payload == {"status": "ready"}, "unexpected API readiness response"
PY
health=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 http://127.0.0.1:8080/healthz)
unauth=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 http://127.0.0.1:8080/v1/assets)
unverified_collector=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 \
  --header 'Authorization: Collector synthetic-not-authenticated' \
  --header 'Content-Type: application/json' \
  --data '{"external_ref":"synthetic-host","category":"endpoint","label":"Synthetic host"}' \
  http://127.0.0.1:8080/v1/collector/assets)
test "$health" = 200 || { echo "Liveness failed"; exit 1; }
test "$unauth" = 401 || { echo "Missing user credential was not rejected"; exit 1; }
test "$unverified_collector" = 403 || { echo "Missing verified collector mTLS was not rejected"; exit 1; }
echo "API container smoke PASS: non-root read-only runtime, Postgres FORCE RLS readiness, liveness, user 401, collector mTLS 403"
