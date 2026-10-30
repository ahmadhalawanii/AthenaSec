#!/usr/bin/env bash

# AthenaSec Secrets Library
#
# Central helper functions for securely creating, storing, and reading
# AthenaSec installation secrets.
#
# Secret storage:
#   /etc/athenasec/secrets/
#
# Security rules:
# - Secrets directory: root:root 700
# - Secret files:      root:root 600
# - Existing secrets are never regenerated automatically
# - Secret creation functions do not print secret values
# - Secrets must never be committed to Git

ATHENASEC_CONFIG_DIR="/etc/athenasec"
ATHENASEC_SECRETS_DIR="${ATHENASEC_CONFIG_DIR}/secrets"


athenasec_require_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "AthenaSec secret operations must run as root." >&2
        return 1
    fi
}


validate_secret_path() {
    local relative_path="${1:-}"

    if [ -z "${relative_path}" ]; then
        echo "Secret path cannot be empty." >&2
        return 1
    fi

    # Paths must always be relative to /etc/athenasec/secrets.
    if [[ "${relative_path}" = /* ]]; then
        echo "Secret path must be relative." >&2
        return 1
    fi

    # Prevent directory traversal.
    if [[ "${relative_path}" == ".." ]] ||
       [[ "${relative_path}" == ../* ]] ||
       [[ "${relative_path}" == */../* ]] ||
       [[ "${relative_path}" == */.. ]]; then
        echo "Invalid secret path." >&2
        return 1
    fi

    # Restrict filenames to predictable characters.
    if [[ ! "${relative_path}" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        echo "Secret path contains invalid characters." >&2
        return 1
    fi
}


ensure_secrets_directory() {
    athenasec_require_root || return 1

    install \
        -d \
        -m 700 \
        -o root \
        -g root \
        "${ATHENASEC_SECRETS_DIR}"

    for directory in internal wazuh cortex misp; do
        install \
            -d \
            -m 700 \
            -o root \
            -g root \
            "${ATHENASEC_SECRETS_DIR}/${directory}"
    done
}


secret_exists() {
    local relative_path="${1:-}"

    validate_secret_path "${relative_path}" || return 1

    [ -s "${ATHENASEC_SECRETS_DIR}/${relative_path}" ]
}


_generate_random_secret() {
    local length="${1:-48}"
    local byte_count
    local random_value

    if ! [[ "${length}" =~ ^[0-9]+$ ]] || [ "${length}" -lt 16 ]; then
        echo "Invalid secret length." >&2
        return 1
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl is required for secret generation." >&2
        return 1
    fi

    # Hex encoding produces two characters per random byte.
    byte_count=$(( (length + 1) / 2 ))

    random_value="$(openssl rand -hex "${byte_count}")" || return 1

    printf '%s' "${random_value:0:length}"
}


store_secret() {
    local relative_path="${1:-}"
    local value="${2:-}"
    local destination
    local parent_directory
    local temporary_file

    athenasec_require_root || return 1
    validate_secret_path "${relative_path}" || return 1

    if [ -z "${value}" ]; then
        echo "Refusing to store an empty secret." >&2
        return 1
    fi

    destination="${ATHENASEC_SECRETS_DIR}/${relative_path}"
    parent_directory="$(dirname "${destination}")"

    install \
        -d \
        -m 700 \
        -o root \
        -g root \
        "${parent_directory}"

    temporary_file="$(mktemp "${parent_directory}/.athenasec-secret.XXXXXX")" \
        || return 1

    chmod 600 "${temporary_file}"
    chown root:root "${temporary_file}"

    if ! printf '%s\n' "${value}" > "${temporary_file}"; then
        rm -f "${temporary_file}"
        return 1
    fi

    mv -f "${temporary_file}" "${destination}"

    chown root:root "${destination}"
    chmod 600 "${destination}"
}


ensure_secret() {
    local relative_path="${1:-}"
    local length="${2:-48}"
    local generated_secret

    athenasec_require_root || return 1
    validate_secret_path "${relative_path}" || return 1

    if secret_exists "${relative_path}"; then
        return 0
    fi

    generated_secret="$(_generate_random_secret "${length}")" || return 1

    store_secret "${relative_path}" "${generated_secret}" || return 1

    # Remove the shell variable as soon as it is no longer needed.
    unset generated_secret
}


read_secret() {
    local relative_path="${1:-}"
    local path

    athenasec_require_root || return 1
    validate_secret_path "${relative_path}" || return 1

    path="${ATHENASEC_SECRETS_DIR}/${relative_path}"

    if [ ! -f "${path}" ]; then
        echo "Secret does not exist: ${relative_path}" >&2
        return 1
    fi

    cat "${path}"
}
