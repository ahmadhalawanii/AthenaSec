import os

from app.services.audit_store import (
    PostgresAuditStore,
    SQLiteAuditStore,
)
from app.services.investigation_store import (
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)
from app.services.incident_response_store import (
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.runtime_control_store import (
    PostgresRuntimeControlStore,
    SQLiteRuntimeControlStore,
)
from app.services.target_protection_store import (
    PostgresTargetProtectionStore,
    SQLiteTargetProtectionStore,
)
from app.services.containment_expiry_store import (
    PostgresContainmentExpiryStore,
    SQLiteContainmentExpiryStore,
)


def build_persistence_stores_from_env(
    *,
    postgres_investigation_store_class=(
        PostgresInvestigationStore
    ),
    postgres_audit_store_class=(
        PostgresAuditStore
    ),
    sqlite_investigation_store_class=(
        SQLiteInvestigationStore
    ),
    sqlite_audit_store_class=(
        SQLiteAuditStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        database_path = os.getenv(
            "ATHENASEC_DB_PATH",
            "data/athenasec.db",
        )

        investigation_store = (
            sqlite_investigation_store_class(
                database_path
            )
        )

        audit_store = (
            sqlite_audit_store_class(
                database_path
            )
        )

        return (
            investigation_store,
            audit_store,
        )

    if backend != "postgres":
        raise ValueError(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND: "
            f"{backend}"
        )

    database_url = os.getenv(
        "ATHENASEC_DATABASE_URL"
    )

    if not database_url:
        raise ValueError(
            "ATHENASEC_DATABASE_URL is required."
        )

    investigation_store = (
        postgres_investigation_store_class(
            database_url
        )
    )

    audit_store = (
        postgres_audit_store_class(
            database_url
        )
    )

    return (
        investigation_store,
        audit_store,
    )


def build_incident_response_store_from_env(
    *,
    postgres_response_store_class=(
        PostgresIncidentResponseStore
    ),
    sqlite_response_store_class=(
        SQLiteIncidentResponseStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        database_path = os.getenv(
            "ATHENASEC_DB_PATH",
            "data/athenasec.db",
        )

        return (
            sqlite_response_store_class(
                database_path
            )
        )

    if backend != "postgres":
        raise ValueError(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND: "
            f"{backend}"
        )

    database_url = os.getenv(
        "ATHENASEC_DATABASE_URL"
    )

    if not database_url:
        raise ValueError(
            "ATHENASEC_DATABASE_URL is required."
        )

    return (
        postgres_response_store_class(
            database_url
        )
    )


def build_runtime_control_store_from_env(
    *,
    postgres_runtime_store_class=(
        PostgresRuntimeControlStore
    ),
    sqlite_runtime_store_class=(
        SQLiteRuntimeControlStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        database_path = os.getenv(
            "ATHENASEC_DB_PATH",
            "data/athenasec.db",
        )

        return (
            sqlite_runtime_store_class(
                database_path
            )
        )

    if backend != "postgres":
        raise ValueError(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND: "
            f"{backend}"
        )

    database_url = os.getenv(
        "ATHENASEC_DATABASE_URL"
    )

    if not database_url:
        raise ValueError(
            "ATHENASEC_DATABASE_URL is required."
        )

    return (
        postgres_runtime_store_class(
            database_url
        )
    )


def build_target_protection_store_from_env(
    *,
    postgres_store_class=(
        PostgresTargetProtectionStore
    ),
    sqlite_store_class=(
        SQLiteTargetProtectionStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        database_path = os.getenv(
            "ATHENASEC_DB_PATH",
            "data/athenasec.db",
        )

        return sqlite_store_class(
            database_path
        )

    if backend != "postgres":
        raise ValueError(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND: "
            f"{backend}"
        )

    database_url = os.getenv(
        "ATHENASEC_DATABASE_URL"
    )

    if not database_url:
        raise ValueError(
            "ATHENASEC_DATABASE_URL is required."
        )

    return postgres_store_class(
        database_url
    )


def build_containment_expiry_store_from_env(
    *,
    postgres_store_class=(
        PostgresContainmentExpiryStore
    ),
    sqlite_store_class=(
        SQLiteContainmentExpiryStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        database_path = os.getenv(
            "ATHENASEC_DB_PATH",
            "data/athenasec.db",
        )

        return sqlite_store_class(
            database_path
        )

    if backend != "postgres":
        raise ValueError(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND: "
            f"{backend}"
        )

    database_url = os.getenv(
        "ATHENASEC_DATABASE_URL"
    )

    if not database_url:
        raise ValueError(
            "ATHENASEC_DATABASE_URL is required."
        )

    return postgres_store_class(
        database_url
    )
