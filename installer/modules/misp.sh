#!/usr/bin/env bash
set -euo pipefail

ATHENASEC_ROOT="/opt/athenasec"
INSTALLER_DIR="${ATHENASEC_ROOT}/installer"

SECRETS_LIB="${INSTALLER_DIR}/lib/secrets.sh"
SECRETS_CONFIG="${INSTALLER_DIR}/configs/secrets.conf"

MISP_DIR="${ATHENASEC_ROOT}/misp-docker"
COMPOSE_FILE="${MISP_DIR}/docker-compose.yml"
ENV_FILE="${MISP_DIR}/.env"
ENV_TEMPLATE="${MISP_DIR}/template.env"
MISP_CONFIG_DIR="${MISP_DIR}/configs"

MISP_HTTPS_PORT="9445"
MISP_CORE_FLAVOR="slim"
MISP_MODULES_FLAVOR="slim"
MISP_ADMIN_EMAIL="admin@athenasec.local"
MISP_ADMIN_ORG="AthenaSec"

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
    [ -f "$SECRETS_LIB" ] \
        || die "Missing secrets helper: $SECRETS_LIB"

    [ -f "$SECRETS_CONFIG" ] \
        || die "Missing secrets config: $SECRETS_CONFIG"

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

    command -v sed >/dev/null 2>&1 \
        || die "sed is required."

    command -v grep >/dev/null 2>&1 \
        || die "grep is required."
}

check_stack_files() {
    [ -d "$MISP_DIR" ] \
        || die "MISP directory not found: $MISP_DIR"

    [ -f "$COMPOSE_FILE" ] \
        || die "Missing MISP Docker Compose file."

    [ -f "$ENV_TEMPLATE" ] \
        || die "Missing MISP template.env."
}

clean_optional_compose_variables() {
    log "Cleaning optional MISP Compose variables..."

    python3 - "$COMPOSE_FILE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()

optional_prefixes = (
    "AAD_",
    "APACHESECUREAUTH_",
    "LDAP_",
    "LDAPAUTH_",
    "OIDC_",
    "CUSTOM_AUTH_",
    "PROXY_",
    "S3_",
    "SES_",
    "SMARTHOST_",
    "SUPERVISOR_",
    "SYNCSERVERS",
    "PYPI_",
)

optional_exact = {
    "ATTACHMENTS_DIR",
    "CACHE_FEED_INTERVAL",
    "COMPOSE_PROFILES",
    "CONTENT_SECURITY_POLICY",
    "CORE_COMMIT",
    "CRON_PULLALL",
    "CRON_PUSHALL",
    "CRON_USER_ID",
    "DEBUG",
    "DISABLE_CA_REFRESH",
    "DISABLE_IPV6",
    "DISABLE_REDIS_SNAPSHOT",
    "DISABLE_SSL_REDIRECT",
    "ENABLE_BACKGROUND_UPDATES",
    "ENABLE_DB_SETTINGS",
    "ENABLE_THEMES",
    "FASTCGI_STATUS_LISTEN",
    "FETCH_FEED_INTERVAL",
    "GPG_PASSPHRASE",
    "GUARD_ARGS",
    "GUARD_COMMIT",
    "HSTS_MAX_AGE",
    "MISP_CONTACT",
    "MISP_EMAIL",
    "MODULES_COMMIT",
    "MYSQL_TLS_CA",
    "MYSQL_TLS_CERT",
    "MYSQL_TLS_KEY",
    "NGINX_SET_REAL_IP_FROM",
    "NGINX_X_FORWARDED_FOR",
    "PHP_SESSION_COOKIE_DOMAIN",
    "SALT",
    "SMTP_FQDN",
    "STUNNEL",
    "STUNNEL_CONFIG",
    "UUID",
    "X_FRAME_OPTIONS",
}

def repl(match):
    name = match.group(1)

    if name == "redis_snapshot":
        return match.group(0)

    if name.startswith(optional_prefixes) or name in optional_exact:
        return "${" + name + ":-}"

    return match.group(0)

new_text = re.sub(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
    repl,
    text,
)

if new_text != text:
    path.write_text(new_text)
PY
}

compose() {
    docker compose \
        -f "$COMPOSE_FILE" \
        --env-file "$ENV_FILE" \
        "$@"
}

existing_misp_instance() {
    # Existing containers indicate that this installation has already
    # initialized MISP at least once.
    if [ -f "$ENV_FILE" ]; then
        if docker compose \
            -f "$COMPOSE_FILE" \
            --env-file "$ENV_FILE" \
            ps -aq db 2>/dev/null \
            | grep -q .; then

            return 0
        fi
    fi

    # Standard Compose volume name used by this repository.
    if docker volume inspect misp-docker_mysql_data \
        >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

ensure_database_secrets() {
    log "Ensuring MISP database/cache secrets..."

    ensure_secret "$MISP_MYSQL_PASSWORD" 48
    ensure_secret "$MISP_MYSQL_ROOT_PASSWORD" 48
    ensure_secret "$MISP_REDIS_PASSWORD" 48
}

ensure_fresh_bootstrap_secrets() {
    log "Ensuring fresh MISP bootstrap secrets..."

    ensure_secret "$MISP_BOOTSTRAP_ADMIN_PASSWORD" 48
    ensure_secret "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY" 40
    ensure_secret "$MISP_ENCRYPTION_KEY" 64
}

set_env_value() {
    local file="$1"
    local name="$2"
    local value="$3"
    local temp_file

    temp_file="$(mktemp "${file}.tmp.XXXXXX")"
    chmod 600 "$temp_file"

    if grep -qE "^${name}=" "$file"; then
        sed \
            "s|^${name}=.*|${name}=${value}|" \
            "$file" > "$temp_file"
    else
        cat "$file" > "$temp_file"

        printf '\n%s=%s\n' \
            "$name" \
            "$value" \
            >> "$temp_file"
    fi

    mv "$temp_file" "$file"
}

detect_base_url() {
    local reuse_existing="${1:-true}"
    local current=""
    local host_ip

    if [ "$reuse_existing" = "true" ] && [ -f "$ENV_FILE" ]; then
        current="$(
            sed -n 's/^BASE_URL=//p' "$ENV_FILE" \
            | tail -n1
        )"
    fi

    if [ -n "$current" ]; then
        printf '%s' "$current"
        return
    fi

    host_ip="$(
        hostname -I 2>/dev/null \
        | awk '{print $1}'
    )"

    if [ -n "$host_ip" ]; then
        printf 'https://%s:%s' \
            "$host_ip" \
            "$MISP_HTTPS_PORT"
    else
        printf 'https://%s:%s' \
            "$(hostname)" \
            "$MISP_HTTPS_PORT"
    fi
}

prepare_existing_environment() {
    log "Preparing existing MISP environment..."

    [ -f "$ENV_FILE" ] \
        || die "Existing MISP instance has no .env file."

    local mysql_password
    local mysql_root_password
    local redis_password
    local base_url

    mysql_password="$(read_secret "$MISP_MYSQL_PASSWORD")"
    mysql_root_password="$(read_secret "$MISP_MYSQL_ROOT_PASSWORD")"
    redis_password="$(read_secret "$MISP_REDIS_PASSWORD")"
    base_url="$(detect_base_url)"

    set_env_value \
       "$ENV_FILE" \
       "MYSQL_PASSWORD" \
       "$mysql_password"

    set_env_value \
        "$ENV_FILE" \
        "MYSQL_ROOT_PASSWORD" \
        "$mysql_root_password"

    set_env_value \
        "$ENV_FILE" \
        "REDIS_PASSWORD" \
        "$redis_password"

    set_env_value \
        "$ENV_FILE" \
        "CORE_FLAVOR" \
        "$MISP_CORE_FLAVOR"

    set_env_value \
        "$ENV_FILE" \
        "MODULES_FLAVOR" \
        "$MISP_MODULES_FLAVOR"

    set_env_value \
        "$ENV_FILE" \
        "BASE_URL" \
        "$base_url"

    set_env_value \
        "$ENV_FILE" \
        "CORE_HTTPS_PORT" \
        "$MISP_HTTPS_PORT"

    set_env_value \
        "$ENV_FILE" \
        "DISABLE_PRINTING_PLAINTEXT_CREDENTIALS" \
        "true"

    unset \
        mysql_password \
        mysql_root_password \
        redis_password \
        base_url
}

prepare_fresh_environment() {
    log "Preparing fresh AthenaSec MISP environment..."

    local admin_password
    local admin_key
    local encryption_key
    local mysql_password
    local mysql_root_password
    local redis_password
    local base_url

    cp "$ENV_TEMPLATE" "$ENV_FILE"

    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    admin_password="$(read_secret "$MISP_BOOTSTRAP_ADMIN_PASSWORD")"
    admin_key="$(read_secret "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY")"
    encryption_key="$(read_secret "$MISP_ENCRYPTION_KEY")"

    mysql_password="$(read_secret "$MISP_MYSQL_PASSWORD")"
    mysql_root_password="$(read_secret "$MISP_MYSQL_ROOT_PASSWORD")"
    redis_password="$(read_secret "$MISP_REDIS_PASSWORD")"

    base_url="$(detect_base_url false)"

    set_env_value \
        "$ENV_FILE" \
        "ADMIN_EMAIL" \
        "$MISP_ADMIN_EMAIL"

    set_env_value \
        "$ENV_FILE" \
        "ADMIN_ORG" \
        "$MISP_ADMIN_ORG"

    set_env_value \
        "$ENV_FILE" \
        "ADMIN_PASSWORD" \
        "$admin_password"

    set_env_value \
        "$ENV_FILE" \
        "ADMIN_KEY" \
        "$admin_key"

    set_env_value \
        "$ENV_FILE" \
        "ENCRYPTION_KEY" \
        "$encryption_key"

    set_env_value \
        "$ENV_FILE" \
        "MYSQL_USER" \
        "misp"

    set_env_value \
        "$ENV_FILE" \
        "MYSQL_PASSWORD" \
        "$mysql_password"

    set_env_value \
        "$ENV_FILE" \
        "MYSQL_ROOT_PASSWORD" \
        "$mysql_root_password"

    set_env_value \
        "$ENV_FILE" \
        "MYSQL_DATABASE" \
        "misp"

    set_env_value \
        "$ENV_FILE" \
        "REDIS_PASSWORD" \
        "$redis_password"

    set_env_value \
        "$ENV_FILE" \
        "ENABLE_REDIS_EMPTY_PASSWORD" \
        "false"

    set_env_value \
        "$ENV_FILE" \
        "CORE_FLAVOR" \
        "$MISP_CORE_FLAVOR"

    set_env_value \
        "$ENV_FILE" \
        "MODULES_FLAVOR" \
        "$MISP_MODULES_FLAVOR"

    set_env_value \
        "$ENV_FILE" \
        "BASE_URL" \
        "$base_url"

    set_env_value \
        "$ENV_FILE" \
        "CORE_HTTPS_PORT" \
        "$MISP_HTTPS_PORT"

    set_env_value \
        "$ENV_FILE" \
        "DISABLE_PRINTING_PLAINTEXT_CREDENTIALS" \
        "true"


    unset \
        admin_password \
        admin_key \
        encryption_key \
        mysql_password \
        mysql_root_password \
        redis_password \
        base_url
}

reset_fresh_runtime_config() {
    log "Resetting generated MISP runtime configuration for fresh install..."

    [ -d "$MISP_CONFIG_DIR" ] \
        || die "MISP config directory not found: $MISP_CONFIG_DIR"

    rm -f \
        "${MISP_CONFIG_DIR}/database.php" \
        "${MISP_CONFIG_DIR}/config.php" \
        "${MISP_CONFIG_DIR}/email.php"
}

apply_permissions() {
    log "Applying MISP runtime permissions..."

    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"
}

wait_for_service_healthy() {
    local service="$1"
    local attempts="${2:-90}"
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
                "$container_id" \
                2>/dev/null \
                || true
        )"

        if [ "$health" = "healthy" ]; then
            log "$service: healthy"
            return 0
        fi

        if [ "$health" = "exited" ] \
            || [ "$health" = "dead" ]; then

            die "$service container entered state: $health"
        fi

        sleep "$sleep_seconds"
    done

    die "$service did not become healthy."
}

start_stack() {
    log "Building bundled MISP images..."

    compose build

    log "Starting MISP database and cache..."

    compose up -d db redis

    wait_for_service_healthy db 90 5
    wait_for_service_healthy redis 60 5

    log "Starting MISP modules..."

    compose up -d misp-modules
    wait_for_service_healthy misp-modules 60 5

    log "Starting MISP core..."

    compose up -d misp-core
    wait_for_service_healthy misp-core 120 5

    log "Starting MISP mail service..."

    compose up -d mail
}

verify_misp_https() {
    log "Verifying MISP HTTPS endpoint..."

    local attempts=30

    for ((i = 1; i <= attempts; i++)); do
        if curl \
            --silent \
            --insecure \
            --fail \
            --max-time 10 \
            "https://127.0.0.1:${MISP_HTTPS_PORT}/users/heartbeat" \
            >/dev/null 2>&1; then

            log "MISP HTTPS endpoint: reachable"
            return 0
        fi

        sleep 3
    done

    die "MISP HTTPS endpoint did not respond successfully."
}

verify_stack() {
    log "Final MISP stack status:"
    compose ps

    local required_services=(
        db
        redis
        misp-modules
        misp-core
        mail
    )

    local service
    local container_id
    local state

    for service in "${required_services[@]}"; do
        container_id="$(compose ps -q "$service")"

        [ -n "$container_id" ] \
            || die "MISP service is missing: $service"

        state="$(
            docker inspect \
                --format '{{.State.Status}}' \
                "$container_id"
        )"

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
    clean_optional_compose_variables

    log "Checking MISP..."

    if existing_misp_instance; then
        log "Existing MISP installation detected."

        ensure_database_secrets
        prepare_existing_environment
    else
        log "Fresh MISP installation detected."

        ensure_database_secrets
        ensure_fresh_bootstrap_secrets
        reset_fresh_runtime_config
        prepare_fresh_environment
    fi

    apply_permissions

    start_stack
    verify_misp_https
    verify_stack

    echo
    log "MISP installation/configuration check complete."
}

main "$@"
