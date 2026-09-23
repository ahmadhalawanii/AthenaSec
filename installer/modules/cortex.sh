#!/usr/bin/env bash
set -euo pipefail

ATHENASEC_ROOT="/opt/athenasec"
INSTALLER_DIR="${ATHENASEC_ROOT}/installer"

SECRETS_LIB="${INSTALLER_DIR}/lib/secrets.sh"
SECRETS_CONFIG="${INSTALLER_DIR}/configs/secrets.conf"

CORTEX_DIR="${ATHENASEC_ROOT}/strangebee-docker/prod1-cortex"
COMPOSE_FILE="${CORTEX_DIR}/docker-compose.yml"
ENV_FILE="${CORTEX_DIR}/.env"

CORTEX_ES_DATA_DIR="${CORTEX_DIR}/elasticsearch/data"

CORTEX_STATE_DIR="/var/lib/athenasec/installer"
CORTEX_STATE_FILE="${CORTEX_STATE_DIR}/cortex.initialized"

CORTEX_CONFIG_DIR="${CORTEX_DIR}/cortex/config"
INDEX_FILE="${CORTEX_CONFIG_DIR}/index.conf"
SECRET_FILE="${CORTEX_CONFIG_DIR}/secret.conf"
APPLICATION_FILE="${CORTEX_CONFIG_DIR}/application.conf"

INIT_SCRIPT="${CORTEX_DIR}/scripts/init.sh"

log() {
    echo "[AthenaSec] $*"
}

die() {
    echo "[AthenaSec] ERROR: $*" >&2
    exit 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This module must be run as root."
    fi
}

load_secret_system() {
    [ -f "$SECRETS_LIB" ] || die "Missing secrets helper: $SECRETS_LIB"
    [ -f "$SECRETS_CONFIG" ] || die "Missing secrets config: $SECRETS_CONFIG"

    # shellcheck source=/dev/null
    source "$SECRETS_LIB"

    # shellcheck source=/dev/null
    source "$SECRETS_CONFIG"

    ensure_secrets_directory
}

check_dependencies() {
    command -v docker >/dev/null 2>&1 \
        || die "Docker is not installed."

    docker compose version >/dev/null 2>&1 \
        || die "Docker Compose plugin is not available."

    command -v curl >/dev/null 2>&1 \
        || die "curl is required."

    command -v grep >/dev/null 2>&1 \
        || die "grep is required."

    command -v sed >/dev/null 2>&1 \
        || die "sed is required."
}

check_stack_files() {
    [ -d "$CORTEX_DIR" ] \
        || die "Cortex directory not found: $CORTEX_DIR"

    [ -f "$COMPOSE_FILE" ] \
        || die "Missing Cortex Docker Compose file."

    [ -f "$INIT_SCRIPT" ] \
        || die "Missing Cortex init script."

    [ -f "${CORTEX_DIR}/dot.env.template" ] \
        || die "Missing Cortex dot.env.template."

    [ -f "${CORTEX_CONFIG_DIR}/index.conf.template" ] \
        || die "Missing Cortex index.conf.template."

    [ -f "$APPLICATION_FILE" ] \
        || die "Missing Cortex application.conf."
}

ensure_cortex_secrets() {
    log "Ensuring Cortex bootstrap secrets..."

    ensure_secret "$CORTEX_ELASTICSEARCH_PASSWORD" 64
    ensure_secret "$CORTEX_PLAY_SECRET" 64
    ensure_secret "$CORTEX_BOOTSTRAP_ADMIN_PASSWORD" 48
}

existing_cortex_instance() {
    if [ -f "$CORTEX_STATE_FILE" ]; then
        return 0
    fi

    if secret_exists "$CORTEX_ATHENASEC_SERVICE_API_KEY"; then
        return 0
    fi

    if secret_exists "$CORTEX_BOOTSTRAP_ADMIN_API_KEY"; then
        return 0
    fi

    return 1
}

reset_fresh_cortex_runtime() {
    log "Resetting copied Cortex runtime state for fresh install..."

    if [ -f "$ENV_FILE" ]; then
        docker compose \
            -f "$COMPOSE_FILE" \
            --env-file "$ENV_FILE" \
            down --remove-orphans \
            >/dev/null 2>&1 \
            || true
    fi

    rm -f \
        "$ENV_FILE" \
        "$INDEX_FILE" \
        "$SECRET_FILE"

    mkdir -p "$CORTEX_ES_DATA_DIR"

    find "$CORTEX_ES_DATA_DIR" \
        -mindepth 1 \
        ! -name '.gitkeep' \
        -exec rm -rf -- {} +
}

mark_cortex_initialized() {
    mkdir -p "$CORTEX_STATE_DIR"
    chmod 700 "$CORTEX_STATE_DIR"

    touch "$CORTEX_STATE_FILE"
    chmod 600 "$CORTEX_STATE_FILE"
}

stack_initialized() {
    [ -f "$ENV_FILE" ] \
        && [ -f "$INDEX_FILE" ] \
        && [ -f "$SECRET_FILE" ]
}

run_upstream_initialization() {
    if stack_initialized; then
        log "Cortex upstream configuration already exists."
        return 0
    fi

    log "Running StrangeBee Cortex initialization..."

    (
        cd "$CORTEX_DIR"

        SERVICE_HOSTNAME="$(hostname)" \
        ASSUME_YES=1 \
        bash ./scripts/init.sh --yes
    )

    stack_initialized \
        || die "Cortex initialization did not create expected files."
}

write_runtime_configuration() {
    log "Applying AthenaSec-managed Cortex secrets..."

    local elastic_password
    local play_secret
    local uid_value
    local gid_value
    local hostname_value

    elastic_password="$(read_secret "$CORTEX_ELASTICSEARCH_PASSWORD")"
    play_secret="$(read_secret "$CORTEX_PLAY_SECRET")"

    if [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" -ne 0 ]; then
        uid_value="$SUDO_UID"
        gid_value="${SUDO_GID:-$SUDO_UID}"
    else
        uid_value="$(stat -c '%u' "$ATHENASEC_ROOT")"
        gid_value="$(stat -c '%g' "$ATHENASEC_ROOT")"
    fi

    [ "$uid_value" -ne 0 ] \
        || die "Cortex Elasticsearch cannot run as root. AthenaSec must have a non-root runtime owner."

    hostname_value="$(hostname)"

    umask 077

    cat > "$ENV_FILE" <<EOF
# AthenaSec-managed Cortex runtime configuration

UID=${uid_value}
GID=${gid_value}

elasticsearch_password='${elastic_password}'

cortex_docker_job_directory=${CORTEX_DIR}/cortex/cortex-jobs

cassandra_image_version='4.1.12'
elasticsearch_image_version='8.19.20'
cortex_image_version='4.1.0'
nginx_image_version='1.31.4'

nginx_server_name="${hostname_value}"
nginx_ssl_trusted_certificate=""
EOF

    cat > "$INDEX_FILE" <<EOF
search {
  index = cortex
  user = "elastic"
  password = "${elastic_password}"
}
EOF

    cat > "$SECRET_FILE" <<EOF
play.http.secret.key="${play_secret}"
EOF

    unset elastic_password play_secret
}

verify_application_configuration() {
    log "Checking Cortex application configuration..."

    grep -q 'include file("/etc/cortex/secret.conf")' "$APPLICATION_FILE" \
        || die "Cortex application.conf does not include secret.conf."

    grep -q 'include file("/etc/cortex/index.conf")' "$APPLICATION_FILE" \
        || die "Cortex application.conf does not include index.conf."
}

apply_permissions() {
    log "Applying Cortex permissions..."

    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    chown 1001:1001 "$INDEX_FILE" "$SECRET_FILE"
    chmod 600 "$INDEX_FILE" "$SECRET_FILE"

    if [ -d "${CORTEX_DIR}/cortex/cortex-jobs" ]; then
        chown -R 1001:1001 "${CORTEX_DIR}/cortex/cortex-jobs"
        chmod 700 "${CORTEX_DIR}/cortex/cortex-jobs"
    fi

    if [ -d "${CORTEX_DIR}/cortex/logs" ]; then
        chown -R 1001:1001 "${CORTEX_DIR}/cortex/logs"
        chmod 700 "${CORTEX_DIR}/cortex/logs"
    fi

    local runtime_uid
    runtime_uid="${SUDO_UID:-$(stat -c '%u' "$ATHENASEC_ROOT")}"

    [ "$runtime_uid" -ne 0 ] \
        || die "Unable to determine non-root Cortex runtime UID."

    if [ -d "${CORTEX_DIR}/elasticsearch/data" ]; then
        chown -R "${runtime_uid}:0" \
            "${CORTEX_DIR}/elasticsearch/data"

        chmod -R u+rwX,g+rwX,o-rwx \
            "${CORTEX_DIR}/elasticsearch/data"
    fi

    if [ -d "${CORTEX_DIR}/elasticsearch/logs" ]; then
        chown -R "${runtime_uid}:0" \
            "${CORTEX_DIR}/elasticsearch/logs"

        chmod -R u+rwX,g+rwX,o-rwx \
            "${CORTEX_DIR}/elasticsearch/logs"
    fi

    unset runtime_uid
}

verify_compose_expectations() {
    log "Checking AthenaSec Cortex Compose settings..."

    grep -q "container_name: cortex-elasticsearch" "$COMPOSE_FILE" \
        || die "Expected container name cortex-elasticsearch not found."

    grep -q "container_name: cortex-nginx" "$COMPOSE_FILE" \
        || die "Expected container name cortex-nginx not found."

    grep -q "9444:443" "$COMPOSE_FILE" \
        || die "Expected Cortex HTTPS mapping 9444:443 was not found."

    grep -q "es_uri=http://elasticsearch:9200" "$COMPOSE_FILE" \
        || die "Expected Cortex Elasticsearch URI was not found."

    grep -q "http://cortex:9001/api/status" "$COMPOSE_FILE" \
        || die "Expected corrected Cortex healthcheck endpoint was not found."
}

compose() {
    docker compose \
        -f "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        "$@"
}

wait_for_service_healthy() {
    local service="$1"
    local attempts="${2:-60}"
    local sleep_seconds="${3:-5}"

    local container_id
    local health

    container_id="$(compose ps -q "$service")"

    [ -n "$container_id" ] \
        || die "Could not find container for service: $service"

    for ((i = 1; i <= attempts; i++)); do
        health="$(
            docker inspect \
                --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
                "$container_id" 2>/dev/null || true
        )"

        if [ "$health" = "healthy" ]; then
            log "$service: healthy"
            return 0
        fi

        if [ "$health" = "exited" ] || [ "$health" = "dead" ]; then
            die "$service container entered state: $health"
        fi

        sleep "$sleep_seconds"
    done

    die "$service did not become healthy."
}

start_stack() {
    log "Starting Cortex Elasticsearch..."

    compose up -d elasticsearch
    wait_for_service_healthy elasticsearch 60 5

    log "Starting Cortex..."

    compose up -d cortex
    wait_for_service_healthy cortex 60 5

    log "Starting Cortex Nginx..."

    compose up -d nginx
}

verify_cortex_api() {
    log "Verifying Cortex API..."

    local container_id
    local attempts=30

    container_id="$(compose ps -q cortex)"

    [ -n "$container_id" ] \
        || die "Could not find Cortex container."

    for ((i = 1; i <= attempts; i++)); do
        if docker exec "$container_id" \
            curl \
                --silent \
                --fail \
                --max-time 5 \
                http://127.0.0.1:9001/api/status \
                >/dev/null 2>&1; then

            log "Cortex API: reachable"
            return 0
        fi

        sleep 3
    done

    die "Cortex API did not respond successfully."
}

verify_stack() {
    log "Final Cortex stack status:"
    compose ps

    local required_services=(
        elasticsearch
        cortex
        nginx
    )

    local service
    local container_id
    local state

    for service in "${required_services[@]}"; do
        container_id="$(compose ps -q "$service")"

        [ -n "$container_id" ] \
            || die "Service is missing: $service"

        state="$(docker inspect --format '{{.State.Status}}' "$container_id")"

        [ "$state" = "running" ] \
            || die "$service is not running. Current state: $state"

        log "$service: running"
    done
}

main() {
    require_root
    load_secret_system
    check_dependencies
    check_stack_files

    log "Checking Cortex..."

    if existing_cortex_instance; then
        log "Existing Cortex installation detected."
    else
        log "Fresh Cortex installation detected."
        reset_fresh_cortex_runtime
    fi

    ensure_cortex_secrets
    run_upstream_initialization
    write_runtime_configuration
    verify_application_configuration
    apply_permissions
    verify_compose_expectations

    start_stack
    verify_cortex_api
    verify_stack

    mark_cortex_initialized

    echo
    log "Cortex installation/configuration check complete."
}

main "$@"
