import os

from app.services.audit_store import (
    PostgresAuditStore,
    SQLiteAuditStore,
)
from app.services.investigation_store import (
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
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