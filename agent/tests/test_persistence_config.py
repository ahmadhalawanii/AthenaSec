import pytest
from unittest.mock import MagicMock

from app.services.persistence_config import (
    build_persistence_stores_from_env,
)


def test_build_persistence_stores_uses_postgres_database_url(
    monkeypatch,
):
    investigation_store_class = MagicMock()
    audit_store_class = MagicMock()

    monkeypatch.setenv(
        "ATHENASEC_DATABASE_URL",
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
    )

    investigation_store, audit_store = (
        build_persistence_stores_from_env(
            postgres_investigation_store_class=(
                investigation_store_class
            ),
            postgres_audit_store_class=(
                audit_store_class
            ),
        )
    )

    investigation_store_class.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    audit_store_class.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    assert (
        investigation_store
        is investigation_store_class.return_value
    )

    assert (
        audit_store
        is audit_store_class.return_value
    )

def test_build_persistence_stores_uses_sqlite_when_explicitly_configured(
    monkeypatch,
):
    investigation_store_class = MagicMock()
    audit_store_class = MagicMock()

    monkeypatch.setenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "sqlite",
    )

    monkeypatch.setenv(
        "ATHENASEC_DB_PATH",
        "data/athenasec-test.db",
    )

    monkeypatch.delenv(
        "ATHENASEC_DATABASE_URL",
        raising=False,
    )

    investigation_store, audit_store = (
        build_persistence_stores_from_env(
            sqlite_investigation_store_class=(
                investigation_store_class
            ),
            sqlite_audit_store_class=(
                audit_store_class
            ),
        )
    )

    investigation_store_class.assert_called_once_with(
        "data/athenasec-test.db"
    )

    audit_store_class.assert_called_once_with(
        "data/athenasec-test.db"
    )

    assert (
        investigation_store
        is investigation_store_class.return_value
    )

    assert (
        audit_store
        is audit_store_class.return_value
    )

def test_create_app_uses_persistence_builder_when_stores_not_injected(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "sqlite",
    )

    monkeypatch.setenv(
        "ATHENASEC_DB_PATH",
        str(
            tmp_path
            / "athenasec-import.db"
        ),
    )

    import app.main as main_module

    investigation_store = MagicMock()
    audit_store = MagicMock()

    builder = MagicMock(
        return_value=(
            investigation_store,
            audit_store,
        )
    )

    monkeypatch.setattr(
        main_module,
        "build_persistence_stores_from_env",
        builder,
    )

    legacy_investigation_store = MagicMock()
    legacy_audit_store = MagicMock()

    monkeypatch.setattr(
        main_module,
        "SQLiteInvestigationStore",
        legacy_investigation_store,
    )

    monkeypatch.setattr(
        main_module,
        "SQLiteAuditStore",
        legacy_audit_store,
    )

    main_module.create_app(
        investigation_graph=MagicMock(),
        response_executor=MagicMock(),
    )

    builder.assert_called_once_with()

    legacy_investigation_store.assert_not_called()
    legacy_audit_store.assert_not_called()

def test_create_app_does_not_build_persistence_when_both_stores_injected(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "sqlite",
    )

    monkeypatch.setenv(
        "ATHENASEC_DB_PATH",
        str(
            tmp_path
            / "athenasec-import.db"
        ),
    )

    import app.main as main_module

    builder = MagicMock()

    monkeypatch.setattr(
        main_module,
        "build_persistence_stores_from_env",
        builder,
    )

    investigation_store = MagicMock()
    audit_store = MagicMock()

    main_module.create_app(
        investigation_graph=MagicMock(),
        investigation_store=investigation_store,
        audit_store=audit_store,
        response_executor=MagicMock(),
    )

    builder.assert_not_called()

def test_postgres_default_requires_database_url(
    monkeypatch,
):
    import pytest

    monkeypatch.delenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        raising=False,
    )

    monkeypatch.delenv(
        "ATHENASEC_DATABASE_URL",
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match="ATHENASEC_DATABASE_URL",
    ):
        build_persistence_stores_from_env()

def test_persistence_config_rejects_unknown_backend(
    monkeypatch,
):
    monkeypatch.setenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "mysql",
    )

    monkeypatch.setenv(
        "ATHENASEC_DATABASE_URL",
        "postgresql://unused",
    )

    class UnexpectedStore:
        def __init__(
            self,
            *args,
            **kwargs,
        ):
            raise AssertionError(
                "Persistence store should not "
                "be constructed for an "
                "unsupported backend."
            )

    with pytest.raises(
        ValueError,
        match=(
            "Unsupported "
            "ATHENASEC_PERSISTENCE_BACKEND"
        ),
    ):
        build_persistence_stores_from_env(
            postgres_investigation_store_class=(
                UnexpectedStore
            ),
            postgres_audit_store_class=(
                UnexpectedStore
            ),
        )