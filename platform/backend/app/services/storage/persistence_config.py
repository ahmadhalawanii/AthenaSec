import os

from app.services.runtime.settings_store import PostgresSettingsStore, SQLiteSettingsStore
from app.services.investigations.alert_workflow_store import (
    PostgresAlertWorkflowStore,
    SQLiteAlertWorkflowStore,
)
from app.services.audit.audit_store import (
    PostgresAuditStore,
    SQLiteAuditStore,
)
from app.services.cases.case_workflow_store import (
    PostgresCaseWorkflowStore,
    SQLiteCaseWorkflowStore,
)
from app.services.policy.action_policy_store import (
    PostgresActionPolicyStore,
    SQLiteActionPolicyStore,
)
from app.services.policy.response_policy_store import (
    PostgresResponsePolicyStore,
    SQLiteResponsePolicyStore,
)
from app.services.health.health_event_store import (
    PostgresHealthEventStore,
    SQLiteHealthEventStore,
)
from app.services.audit.operator_audit_store import (
    PostgresOperatorAuditStore,
    SQLiteOperatorAuditStore,
)
from app.services.investigations.investigation_store import (
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)
from app.services.storage.incident_response_store import (
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.runtime.runtime_control_store import (
    PostgresRuntimeControlStore,
    SQLiteRuntimeControlStore,
)
from app.services.execution.target_protection_store import (
    PostgresTargetProtectionStore,
    SQLiteTargetProtectionStore,
)
from app.services.containment.containment_expiry_store import (
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


def build_operator_audit_store_from_env(
    *,
    postgres_store_class=(
        PostgresOperatorAuditStore
    ),
    sqlite_store_class=(
        SQLiteOperatorAuditStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        return sqlite_store_class(
            os.getenv(
                "ATHENASEC_DB_PATH",
                "data/athenasec.db",
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

    return postgres_store_class(
        database_url
    )


def build_case_workflow_store_from_env(
    *,
    postgres_store_class=(
        PostgresCaseWorkflowStore
    ),
    sqlite_store_class=(
        SQLiteCaseWorkflowStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        return sqlite_store_class(
            os.getenv(
                "ATHENASEC_DB_PATH",
                "data/athenasec.db",
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

    return postgres_store_class(
        database_url
    )


def build_response_policy_store_from_env(
    *,
    postgres_store_class=(
        PostgresResponsePolicyStore
    ),
    sqlite_store_class=(
        SQLiteResponsePolicyStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        return sqlite_store_class(
            os.getenv(
                "ATHENASEC_DB_PATH",
                "data/athenasec.db",
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

    return postgres_store_class(
        database_url
    )


def build_action_policy_store_from_env(
    *,
    postgres_store_class=PostgresActionPolicyStore,
    sqlite_store_class=SQLiteActionPolicyStore,
):
    """The store for the admin's action whitelist/blacklist, which the agent enforces."""
    backend = os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower()

    if backend == "sqlite":
        return sqlite_store_class(os.getenv("ATHENASEC_DB_PATH", "data/athenasec.db"))

    if backend != "postgres":
        raise ValueError(f"Unsupported ATHENASEC_PERSISTENCE_BACKEND: {backend}")

    database_url = os.getenv("ATHENASEC_DATABASE_URL")

    if not database_url:
        raise ValueError("ATHENASEC_DATABASE_URL is required.")

    return postgres_store_class(database_url)


def build_health_event_store_from_env(
    *,
    postgres_store_class=(
        PostgresHealthEventStore
    ),
    sqlite_store_class=(
        SQLiteHealthEventStore
    ),
):
    backend = os.getenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "postgres",
    ).strip().lower()

    if backend == "sqlite":
        return sqlite_store_class(
            os.getenv(
                "ATHENASEC_DB_PATH",
                "data/athenasec.db",
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

    return postgres_store_class(
        database_url
    )


def build_alert_workflow_store_from_env(
    *,
    postgres_store_class=PostgresAlertWorkflowStore,
    sqlite_store_class=SQLiteAlertWorkflowStore,
):
    # Same backend choice as the case workflow store
    return build_case_workflow_store_from_env(
        postgres_store_class=postgres_store_class,
        sqlite_store_class=sqlite_store_class,
    )


def build_settings_store_from_env(
    *,
    postgres_store_class=PostgresSettingsStore,
    sqlite_store_class=SQLiteSettingsStore,
):
    return build_case_workflow_store_from_env(
        postgres_store_class=postgres_store_class,
        sqlite_store_class=sqlite_store_class,
    )
