#!/usr/bin/env bash
# Move the AthenaSec Docker container from SQLite to PostgreSQL.
#
#   sudo bash migrate-container-to-postgres.sh /path/to/backend
#
# /path/to/backend is the folder with compose.yaml, .env and data/athenasec.db
# (already updated to the PostgreSQL compose.yaml from this repository).
#
# What it does, stopping at the first problem:
#   1. stops and removes the old SQLite container (its data stays in ./data)
#   2. copies data/athenasec.db* to rollback/sqlite-<time>/ and checks the copy byte for byte
#   3. adds missing secrets to .env (database password, Wazuh ingest key, TOTP key), chmod 600
#   4. builds the image, starts PostgreSQL, runs `alembic upgrade head`
#   5. dry run: copy + verify inside a transaction, then roll back
#   6. real copy (verified before COMMIT), then a second independent verification
#   7. starts the backend on PostgreSQL and checks the Wazuh ingest key is accepted
#
# It never edits or deletes data/athenasec.db or your own backup.
# Cortex execution stays disabled (compose.yaml forces AUTONOMOUS_RESPONSE_ENABLED=false).

set -euo pipefail

DIR="${1:?Usage: sudo bash $0 /path/to/backend (the folder with compose.yaml and data/athenasec.db)}"
cd "$DIR"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\n\033[31mSTOPPED: %s\033[0m\n' "$*" >&2; exit 1; }

[ -f compose.yaml ] || die "no compose.yaml in $DIR"
grep -q "athenasec-postgres" compose.yaml || die "compose.yaml is the old SQLite version. Copy the new one from the repository first."
[ -f data/athenasec.db ] || die "no data/athenasec.db in $DIR"
[ -f .env ] || die "no .env in $DIR (copy .env.example to .env and fill it in first)"
command -v docker >/dev/null || die "docker is not installed"

STAMP="$(date +%Y%m%d-%H%M%S)"
ROLLBACK="$DIR/rollback/sqlite-$STAMP"

say "1/7  Stopping the old SQLite container"
if docker ps -a --format '{{.Names}}' | grep -qx athenasec-agent; then
  docker stop athenasec-agent >/dev/null
  docker rm athenasec-agent >/dev/null
  echo "old athenasec-agent container stopped and removed (data/ is untouched)"
else
  echo "no old athenasec-agent container"
fi

PORT="$(grep -E '^ATHENASEC_API_PORT=' .env | cut -d= -f2- || true)"; PORT="${PORT:-8000}"
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  die "port $PORT is already used by another program (e.g. the systemd athenasec-backend).
Stop that program, or add ATHENASEC_API_PORT=8001 to .env, then run this again."
fi

say "2/7  Rollback copy of the SQLite database"
mkdir -p "$ROLLBACK"
cp -a data/athenasec.db* "$ROLLBACK/"
for f in data/athenasec.db*; do
  cmp -s "$f" "$ROLLBACK/$(basename "$f")" || die "copy of $f is not identical"
done
( cd "$ROLLBACK" && sha256sum athenasec.db* > SHA256SUMS )
cp -a .env "$DIR/rollback/env-before-postgres-$STAMP"
chmod 600 "$DIR/rollback/env-before-postgres-$STAMP"
cat "$ROLLBACK/SHA256SUMS"
echo "saved in $ROLLBACK"

say "3/7  Secrets in .env"
add_secret() {  # name, generator
  if grep -Eq "^$1=.+" .env; then
    echo "$1 already set"
  else
    sed -i "/^$1=/d" .env
    printf '%s=%s\n' "$1" "$($2)" >> .env
    echo "$1 generated"
  fi
}
add_secret ATHENASEC_PG_PASSWORD "openssl rand -hex 24"
add_secret ATHENASEC_WAZUH_INGEST_KEY "openssl rand -hex 32"
add_secret ATHENASEC_TOTP_MASTER_KEY "openssl rand -hex 32"
chmod 600 .env

say "4/7  Building the image, starting PostgreSQL, applying migrations"
docker compose build
docker compose up -d postgres
docker compose run --rm migrate

MIGRATE=(docker compose run --rm --no-deps -v "$ROLLBACK:/migrate" athenasec-agent
         python -m app.services.storage.sqlite_to_postgres --sqlite /migrate/athenasec.db)

say "5/7  Dry run (nothing is written)"
"${MIGRATE[@]}" --dry-run || die "dry run failed; PostgreSQL is unchanged. Send the output above."

say "6/7  Copying and verifying"
"${MIGRATE[@]}" --report /migrate/migration-report.json || die "copy failed and was rolled back; PostgreSQL is unchanged."
"${MIGRATE[@]}" --verify-only || die "second verification failed. Do not switch over; see the rollback steps."
cmp -s data/athenasec.db "$ROLLBACK/athenasec.db" || die "data/athenasec.db changed during the run"

say "7/7  Starting the backend on PostgreSQL"
docker compose up -d athenasec-agent
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break
  sleep 2
done
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null || die "backend did not come up: docker compose logs athenasec-agent"

KEY="$(grep -E '^ATHENASEC_WAZUH_INGEST_KEY=' .env | cut -d= -f2-)"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/api/v1/integrations/wazuh/alerts" \
  -H 'content-type: application/json' -H "x-athenasec-integration-key: $KEY" -d '{}')"
unset KEY
case "$CODE" in
  400|422) echo "Wazuh ingest endpoint: key accepted (HTTP $CODE for an empty test body, nothing stored)";;
  503) die "ingest endpoint still answers 503: ATHENASEC_WAZUH_INGEST_KEY did not reach the container";;
  *) die "ingest endpoint answered HTTP $CODE";;
esac

say "DONE"
echo "Backend:  http://127.0.0.1:$PORT  (PostgreSQL in Docker volume athenasec_athenasec-pgdata)"
echo "Report:   $ROLLBACK/migration-report.json"
echo "Rollback: $ROLLBACK  (SQLite copy + SHA256SUMS), old .env in $DIR/rollback/env-before-postgres-$STAMP"
echo "Next:     put the same ATHENASEC_WAZUH_INGEST_KEY in the Wazuh <integration> <api_key> for port $PORT"
