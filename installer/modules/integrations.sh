#!/usr/bin/env bash
set -euo pipefail

ATHENASEC_ROOT="/opt/athenasec"
INSTALLER_DIR="${ATHENASEC_ROOT}/installer"

SECRETS_LIB="${INSTALLER_DIR}/lib/secrets.sh"
SECRETS_CONFIG="${INSTALLER_DIR}/configs/secrets.conf"

CORTEX_DIR="${ATHENASEC_ROOT}/strangebee-docker/prod1-cortex"
MISP_DIR="${ATHENASEC_ROOT}/misp-docker"


log() {
    echo "[AthenaSec] $*"
}

die() {
    echo "[AthenaSec] ERROR: $*" >&2
    exit 1
}

require_root() {
    [ "$(id -u)" -eq 0 ] \
        || die "This module must be run as root."
}

load_secret_system() {
    [ -f "$SECRETS_LIB" ] \
        || die "Missing secrets helper."

    [ -f "$SECRETS_CONFIG" ] \
        || die "Missing secrets inventory."

    # shellcheck source=/dev/null
    source "$SECRETS_LIB"

    # shellcheck source=/dev/null
    source "$SECRETS_CONFIG"

    ensure_secrets_directory
}

require_integration_secrets() {
    log "Checking integration secret inventory..."

    local required_paths=(
        "$WAZUH_ATHENASEC_SERVICE_SECRET"
        "$CORTEX_ATHENASEC_SERVICE_API_KEY"
        "$MISP_ATHENASEC_SERVICE_AUTH_KEY"
        "$CORTEX_BOOTSTRAP_ADMIN_PASSWORD"
        "$MISP_BOOTSTRAP_ADMIN_PASSWORD"
        "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY"
    )

    local secret

    for secret in "${required_paths[@]}"; do
        validate_secret_path "$secret" \
            || die "Invalid integration secret path: $secret"
    done

    log "Integration secret inventory: valid"
}

verify_cortex_key() {
    log "Verifying Cortex integration credential..."

    local key
    local container_id

    key="$(read_secret "$CORTEX_ATHENASEC_SERVICE_API_KEY")"

    container_id="$(
        docker compose \
            -f "${CORTEX_DIR}/docker-compose.yml" \
            --env-file "${CORTEX_DIR}/.env" \
            ps -q cortex
    )"

    [ -n "$container_id" ] \
        || die "Cortex container not found."

    docker exec "$container_id" \
        curl \
            --silent \
            --fail \
            --max-time 5 \
            -H "Authorization: Bearer $key" \
            http://127.0.0.1:9001/api/user/athenasec-service \
            >/dev/null \
        || die "Cortex integration credential failed."

    unset key

    log "Cortex integration credential: valid"
}

verify_misp_key() {
    log "Verifying MISP integration credential..."

    local key

    key="$(read_secret "$MISP_ATHENASEC_SERVICE_AUTH_KEY")"

    curl \
        --silent \
        --insecure \
        --fail \
        --max-time 10 \
        -H "Authorization: $key" \
        -H "Accept: application/json" \
        https://127.0.0.1:9445/users/view/me \
        >/dev/null \
        || die "MISP integration credential failed."

    unset key

    log "MISP integration credential: valid"
}

verify_wazuh_api() {
    log "Verifying AthenaSec → Wazuh API..."

    local credential
    local username
    local password
    local token

    if ! secret_exists "$WAZUH_ATHENASEC_SERVICE_SECRET"; then
        die "Wazuh AthenaSec service credential is missing."
    fi

    credential="$(
        read_secret "$WAZUH_ATHENASEC_SERVICE_SECRET"
    )"

    username="$(
        printf '%s\n' "$credential" \
            | sed -n '1p'
    )"

    password="$(
        printf '%s\n' "$credential" \
            | sed -n '2p'
    )"

    unset credential

    [ -n "$username" ] \
        || die "Wazuh API username is empty."

    [ -n "$password" ] \
        || die "Wazuh API password is empty."

    if ! token="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --insecure \
            --max-time 10 \
            -u "${username}:${password}" \
            -X POST \
            "https://127.0.0.1:55000/security/user/authenticate?raw=true"
    )"; then
        unset username password
        die "Wazuh API authentication failed."
    fi

    unset username password

    [ -n "$token" ] \
        || die "Wazuh API authentication returned an empty token."

    #
    # Do not treat a non-empty response as proof of authentication.
    # Perform a real authenticated read request using the returned token.
    #
    curl \
        --silent \
        --show-error \
        --fail \
        --insecure \
        --max-time 10 \
        -H "Authorization: Bearer ${token}" \
        "https://127.0.0.1:55000/manager/status" \
        >/dev/null \
        || {
            unset token
            die "Wazuh API token verification failed."
        }

    unset token

    log "AthenaSec → Wazuh API: reachable and authenticated"
}

cortex_container_id() {
    docker compose \
        -f "${CORTEX_DIR}/docker-compose.yml" \
        --env-file "${CORTEX_DIR}/.env" \
        ps -q cortex
}

cortex_api() {
    local method="$1"
    local endpoint="$2"
    local api_key="$3"
    local data="${4:-}"
    local container_id

    container_id="$(cortex_container_id)"

    [ -n "$container_id" ] \
        || die "Cortex container not found."

    if [ -n "$data" ]; then
        docker exec "$container_id" \
            curl \
                --silent \
                --show-error \
                --fail \
                --request "$method" \
                --header "Authorization: Bearer $api_key" \
                --header "Content-Type: application/json" \
                --data "$data" \
                "http://127.0.0.1:9001${endpoint}"
    else
        docker exec "$container_id" \
            curl \
                --silent \
                --show-error \
                --fail \
                --request "$method" \
                --header "Authorization: Bearer $api_key" \
                "http://127.0.0.1:9001${endpoint}"
    fi
}

ensure_cortex_service_identity() {
    log "Ensuring Cortex AthenaSec service identity..."

    # Existing working installation:
    # if the service key already exists and validates, keep it untouched.
    if secret_exists "$CORTEX_ATHENASEC_SERVICE_API_KEY"; then
        if verify_cortex_key >/dev/null 2>&1; then
            log "Cortex athenasec-service already provisioned."
            return 0
        fi
    fi

    local bootstrap_password
    local bootstrap_response
    local bootstrap_key
    local service_key

    bootstrap_password="$(read_secret "$CORTEX_BOOTSTRAP_ADMIN_PASSWORD")"

    #
    # Bootstrap authentication.
    #
    # On a fresh Cortex installation the installer-owned bootstrap account
    # will be configured as the Cortex superAdmin account.
    #
    bootstrap_response="$(
        docker exec "$(cortex_container_id)" \
            curl \
                --silent \
                --show-error \
                --fail \
                --request POST \
                --header "Content-Type: application/json" \
                --data "{
                    \"user\": \"admin\",
                    \"password\": \"${bootstrap_password}\"
                }" \
                http://127.0.0.1:9001/api/login
    )" || {
        unset bootstrap_password
        # Cortex issues the CSRF token after an authenticated GET.
        docker exec "$container_id" \
            curl \
                --silent \
                --show-error \
                --fail \
                --cookie "$cookie_file" \
                --cookie-jar "$cookie_file" \
                http://127.0.0.1:9001/api/user/current \
                >/dev/null \
            || {
                docker exec "$container_id" \
                    rm -f "$cookie_file" \
                    >/dev/null 2>&1 \
                    || true

                unset container_id cookie_file
                die "Cortex bootstrap administrator session verification failed."
    }
        die "Unable to authenticate Cortex bootstrap administrator."
    }

    unset bootstrap_password

    #
    # Cortex /api/login creates a session. For long-term installer/API
    # operations we want an API key instead.
    #
    # If the bootstrap API key has already been stored, reuse it.
    #
    if secret_exists "$CORTEX_BOOTSTRAP_ADMIN_API_KEY"; then
        bootstrap_key="$(read_secret "$CORTEX_BOOTSTRAP_ADMIN_API_KEY")"
    else
        die "Cortex bootstrap administrator API key is missing."
    fi

    #
    # Ensure AthenaSec organization exists.
    #
    if ! cortex_api \
        GET \
        "/api/organization/athenasec" \
        "$bootstrap_key" \
        >/dev/null 2>&1; then

        log "Creating Cortex AthenaSec organization..."

        cortex_api \
            POST \
            "/api/organization" \
            "$bootstrap_key" \
            '{
                "name": "athenasec",
                "description": "AthenaSec security operations organization",
                "status": "Active"
            }' \
            >/dev/null
    else
        log "Cortex AthenaSec organization already exists."
    fi

    #
    #
    if ! cortex_api \
        GET \
        "/api/user/athenasec-service" \
        "$bootstrap_key" \
        >/dev/null 2>&1; then

        log "Creating Cortex athenasec-service user..."

        cortex_api \
            POST \
            "/api/user" \
            "$bootstrap_key" \
            '{
                "name": "AthenaSec Service",
                "roles": [
                    "read",
                    "analyze"
                ],
                "organization": "athenasec",
                "login": "athenasec-service"
            }' \
            >/dev/null
    else
        log "Cortex athenasec-service user already exists."
    fi

    #
    # Renew the service API key server-side.
    #
    log "Obtaining Cortex athenasec-service API key..."

    service_key="$(
        cortex_api \
            POST \
            "/api/user/athenasec-service/key/renew" \
            "$bootstrap_key"
    )"

    [ -n "$service_key" ] \
        || die "Cortex returned an empty athenasec-service API key."

    store_secret \
        "$CORTEX_ATHENASEC_SERVICE_API_KEY" \
        "$service_key"

    unset service_key
    unset bootstrap_key
    unset bootstrap_response

    log "Cortex AthenaSec service identity provisioned."
}
################33
ensure_cortex_bootstrap_admin() {
    log "Checking Cortex bootstrap administrator..."

    if secret_exists "$CORTEX_ATHENASEC_SERVICE_API_KEY"; then
        if verify_cortex_key >/dev/null 2>&1; then
            log "Existing initialized Cortex installation detected."
            return 0
        fi
    fi

    if secret_exists "$CORTEX_BOOTSTRAP_ADMIN_API_KEY"; then
        local existing_key

        existing_key="$(read_secret "$CORTEX_BOOTSTRAP_ADMIN_API_KEY")"

        if cortex_api \
            GET \
            "/api/user/admin" \
            "$existing_key" \
            >/dev/null 2>&1; then

            unset existing_key
            log "Cortex bootstrap administrator already initialized."
            return 0
        fi

        unset existing_key
    fi

    local bootstrap_password
    local bootstrap_key
    local cookie_file
    local csrf_token
    local cortex_url

    bootstrap_password="$(read_secret "$CORTEX_BOOTSTRAP_ADMIN_PASSWORD")"
    cookie_file="/tmp/athenasec-cortex-bootstrap.cookies"
    cortex_url="https://127.0.0.1:9444"

    rm -f "$cookie_file"

    #
    # First try the existing bootstrap admin.
    # This lets the installer recover from an interrupted bootstrap.
    #
    log "Authenticating Cortex bootstrap administrator..."

    if curl \
        --insecure \
        --silent \
        --show-error \
        --fail \
        --cookie-jar "$cookie_file" \
        --request POST \
        "$cortex_url/api/login" \
        --data "user=admin" \
        --data-urlencode "password=${bootstrap_password}" \
        >/dev/null 2>&1; then

        log "Existing Cortex bootstrap administrator detected."

    else
        rm -f "$cookie_file"

        log "Initializing fresh Cortex database..."

        curl \
            --insecure \
            --silent \
            --show-error \
            --fail \
            --request POST \
            "$cortex_url/api/maintenance/migrate" \
            >/dev/null \
            || {
                unset bootstrap_password cookie_file cortex_url
                die "Cortex database initialization failed."
            }

        log "Creating Cortex bootstrap administrator..."

        curl \
            --insecure \
            --silent \
            --show-error \
            --fail \
            --request POST \
            --header "Content-Type: application/json" \
            --data "{
                \"login\": \"admin\",
                \"name\": \"AthenaSec Bootstrap Administrator\",
                \"roles\": [\"superAdmin\"],
                \"organization\": \"cortex\",
                \"password\": \"${bootstrap_password}\"
            }" \
            "$cortex_url/api/user" \
            >/dev/null \
            || {
                unset bootstrap_password cookie_file cortex_url
                die "Cortex bootstrap administrator creation failed."
            }

        log "Authenticating Cortex bootstrap administrator..."

        curl \
            --insecure \
            --silent \
            --show-error \
            --fail \
            --cookie-jar "$cookie_file" \
            --request POST \
            "$cortex_url/api/login" \
            --data "user=admin" \
            --data-urlencode "password=${bootstrap_password}" \
            >/dev/null \
            || {
                rm -f "$cookie_file"
                unset bootstrap_password cookie_file cortex_url
                die "Cortex bootstrap administrator authentication failed."
            }
    fi

    unset bootstrap_password

    #
    # Cortex sends CORTEX-XSRF-TOKEN after an authenticated GET.
    #
    curl \
        --insecure \
        --silent \
        --show-error \
        --fail \
        --cookie "$cookie_file" \
        --cookie-jar "$cookie_file" \
        "$cortex_url/api/user/current" \
        >/dev/null \
        || {
            rm -f "$cookie_file"
            unset cookie_file cortex_url
            die "Cortex bootstrap administrator session verification failed."
        }

    csrf_token="$(
        awk '$6 == "CORTEX-XSRF-TOKEN" { value=$7 } END { print value }' \
            "$cookie_file"
    )"

    [ -n "$csrf_token" ] \
        || {
            rm -f "$cookie_file"
            unset cookie_file cortex_url
            die "Cortex CSRF token was not returned after authentication."
        }

    log "Generating Cortex bootstrap administrator API key..."

    bootstrap_key="$(
        curl \
            --insecure \
            --silent \
            --show-error \
            --fail \
            --cookie "$cookie_file" \
            --header "X-CORTEX-XSRF-TOKEN: ${csrf_token}" \
            --request POST \
            "$cortex_url/api/user/admin/key/renew"
    )" || {
        rm -f "$cookie_file"
        unset cookie_file csrf_token cortex_url
        die "Cortex bootstrap API key generation failed."
    }

    rm -f "$cookie_file"

    [ -n "$bootstrap_key" ] \
        || die "Cortex returned an empty bootstrap API key."

    store_secret \
        "$CORTEX_BOOTSTRAP_ADMIN_API_KEY" \
        "$bootstrap_key"

    unset bootstrap_key
    unset csrf_token
    unset cookie_file
    unset cortex_url

    log "Cortex bootstrap administrator initialized."
}
####################
misp_container_id() {
    docker compose \
        -f "${MISP_DIR}/docker-compose.yml" \
        --env-file "${MISP_DIR}/.env" \
        ps -q misp-core
}

misp_cake() {
    local container_id

    container_id="$(misp_container_id)"

    [ -n "$container_id" ] \
        || die "MISP core container not found."

    docker exec \
        --user www-data \
        "$container_id" \
        /var/www/MISP/app/Console/cake \
        "$@"
}

wait_for_misp_api() {
    log "Waiting for MISP API to become fully ready..."

    if ! secret_exists "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY"; then
        die "MISP bootstrap administrator Auth Key is missing."
    fi

    local bootstrap_key
    local attempt
    local code

    bootstrap_key="$(read_secret "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY")"

    for attempt in $(seq 1 180); do
        code="$(
            curl \
                --silent \
                --insecure \
                --max-time 5 \
                --output /dev/null \
                --write-out "%{http_code}" \
                -H "Authorization: ${bootstrap_key}" \
                -H "Accept: application/json" \
                "https://127.0.0.1:9445/roles/index.json" \
                || true
        )"

        if [ "$code" = "200" ]; then
            unset bootstrap_key
            log "MISP API: ready"
            return 0
        fi

        sleep 5
    done

    unset bootstrap_key
    die "MISP API did not become ready within 15 minutes."
}

ensure_misp_service_identity() {
    log "Ensuring MISP AthenaSec service identity..."

    #
    # Existing installation:
    # if the stored service Auth Key is valid, leave everything untouched.
    #
    if secret_exists "$MISP_ATHENASEC_SERVICE_AUTH_KEY"; then
        if verify_misp_key >/dev/null 2>&1; then
            log "MISP athenasec-service already provisioned."
            return 0
        fi
    fi

    #
    # Fresh installation requires the installer-owned MISP bootstrap key.
    #
    if ! secret_exists "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY"; then
        die "MISP bootstrap administrator Auth Key is missing."
    fi

    local bootstrap_key
    local user_json
    local user_id
    local role_json
    local role_id
    local service_key
    local key_response

    bootstrap_key="$(read_secret "$MISP_BOOTSTRAP_ADMIN_AUTH_KEY")"

    #
    # Resolve the standard MISP User role dynamically.
    #
    role_json="$(
        curl \
            --silent \
            --insecure \
            --fail \
            --max-time 10 \
            -H "Authorization: ${bootstrap_key}" \
            -H "Accept: application/json" \
            "https://127.0.0.1:9445/roles/index.json"
    )" || {
        unset bootstrap_key
        die "Unable to retrieve MISP roles."
    }

    role_id="$(
        python3 -c '
import json, sys

data = json.load(sys.stdin)

items = data if isinstance(data, list) else data.get("response", data)

for item in items:
    role = item.get("Role", item)

    if role.get("name") == "User":
        print(role.get("id", ""))
        break
' <<< "$role_json"
    )"

    [ -n "$role_id" ] \
        || {
            unset bootstrap_key role_json
            die "Could not resolve the MISP User role."
        }

    #
    # See whether the service user already exists.
    #
    user_json="$(
        curl \
            --silent \
            --insecure \
            --fail \
            --max-time 10 \
            -H "Authorization: ${bootstrap_key}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            -X POST \
            -d '{
                "value": "athenasec-service@athenasec.local",
                "searchall": "athenasec-service@athenasec.local"
            }' \
            "https://127.0.0.1:9445/admin/users/index"
    )" || true

    user_id="$(
        python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

items = data if isinstance(data, list) else data.get("response", [])

for item in items:
    user = item.get("User", item)

    if user.get("email") == "athenasec-service@athenasec.local":
        print(user.get("id", ""))
        break
' <<< "$user_json"
    )"

    #
    # Create the service user if it does not already exist.
    #
    if [ -z "$user_id" ]; then
        log "Creating MISP athenasec-service user..."

        local create_response

        create_response="$(
            curl \
                --silent \
                --insecure \
                --fail \
                --max-time 10 \
                -H "Authorization: ${bootstrap_key}" \
                -H "Accept: application/json" \
                -H "Content-Type: application/json" \
                -X POST \
                -d "{
                    \"email\": \"athenasec-service@athenasec.local\",
                    \"org_id\": \"1\",
                    \"role_id\": \"${role_id}\",
                    \"disabled\": false,
                    \"change_pw\": false
                }" \
                "https://127.0.0.1:9445/admin/users/add"
        )" || {
            unset bootstrap_key role_json role_id user_json
            die "Unable to create MISP athenasec-service user."
        }

        user_id="$(
            python3 -c '
import json, sys

data = json.load(sys.stdin)

user = data.get("User", data.get("user", data))

print(user.get("id", ""))
' <<< "$create_response"
        )"

        [ -n "$user_id" ] \
            || {
                unset bootstrap_key role_json role_id user_json create_response
                die "MISP did not return the new service user ID."
            }

        unset create_response
    else
        log "MISP athenasec-service user already exists."
    fi

    #
    # Advanced Auth Keys are enabled in current MISP.
    # Explicitly create an API key for the service user.
    #
    log "Creating MISP athenasec-service Advanced Auth Key..."

    key_response="$(
        curl \
            --silent \
            --insecure \
            --fail \
            --max-time 10 \
            -H "Authorization: ${bootstrap_key}" \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            -X POST \
            -d "{
                \"user_id\": \"${user_id}\",
                \"comment\": \"AthenaSec Integration\"
            }" \
            "https://127.0.0.1:9445/auth_keys/add/${user_id}"
    )" || {
        unset \
            bootstrap_key \
            user_json \
            role_json \
            user_id \
            role_id

        die "Unable to create MISP athenasec-service Advanced Auth Key."
    }

    service_key="$(
        python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

auth_key = data.get("AuthKey", {})

print(auth_key.get("authkey_raw", ""))
' <<< "$key_response"
    )"

    [ -n "$service_key" ] \
        || {
            unset \
                bootstrap_key \
                key_response \
                user_json \
                role_json \
                user_id \
                role_id

            die "MISP did not return the new service Auth Key."
        }

    #
    # Verify the newly-created key before storing it.
    #
    if ! curl \
        --silent \
        --insecure \
        --fail \
        --max-time 10 \
        -H "Authorization: ${service_key}" \
        -H "Accept: application/json" \
        "https://127.0.0.1:9445/users/view/me" \
        >/dev/null; then

        unset \
            bootstrap_key \
            service_key \
            key_response \
            user_json \
            role_json \
            user_id \
            role_id

        die "New MISP athenasec-service Auth Key failed verification."
    fi

    store_secret \
        "$MISP_ATHENASEC_SERVICE_AUTH_KEY" \
        "$service_key"

    unset \
        bootstrap_key \
        service_key \
        key_response \
        user_json \
        role_json \
        user_id \
        role_id

    log "MISP AthenaSec service identity provisioned."
}

main() {
    require_root
    load_secret_system

    log "Checking AthenaSec integrations..."

    require_integration_secrets

    ensure_cortex_bootstrap_admin
    ensure_cortex_service_identity

    wait_for_misp_api
    ensure_misp_service_identity


    verify_cortex_key
    verify_misp_key
    verify_wazuh_api

    echo
    log "AthenaSec integration checks complete."
}

main "$@"
