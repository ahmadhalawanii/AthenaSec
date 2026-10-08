from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.action_risk_context import (
    make_action_risk_context_provider,
)
from app.services.target_protection import (
    PersistentTargetProtectionRegistry,
    StaticTargetProtectionRegistry,
    TargetProtectionManager,
    build_target_protection_registry_from_env,
    build_target_protection_snapshot,
    initialize_target_protection_store_from_env,
)
from app.services.target_protection_store import (
    InMemoryTargetProtectionStore,
    PostgresTargetProtectionStore,
    SQLiteTargetProtectionStore,
)
from app.schemas import (
    ProposedActionRecord,
)


FIXED_TIME = datetime(
    2026,
    10,
    9,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_action(
    *,
    target_type="ip",
    target="203.0.113.10",
):
    return ProposedActionRecord(
        proposed_action_id="PACT-PROTECT-001",
        incident_id="INC-PROTECT-001",
        investigation_id="INV-PROTECT-001",
        action_type="block_ip",
        target_type=target_type,
        target=target,
        parameters={
            "duration_minutes": 30,
        },
        reversible=True,
        rollback_action_type="unblock_ip",
        rollback_parameters={},
        reason="Contain threat.",
        proposed_at=FIXED_TIME,
    )


def test_exact_ip_can_be_protected():
    registry = (
        StaticTargetProtectionRegistry(
            protected_ips=[
                "203.0.113.10",
            ],
        )
    )

    observation = registry.inspect(
        target_type="ip",
        target="203.0.113.10",
    )

    assert observation.protected_target is True
    assert observation.allowlisted_target is False


def test_ip_cidr_can_protect_target():
    registry = (
        StaticTargetProtectionRegistry(
            protected_ips=[
                "203.0.113.0/24",
            ],
        )
    )

    observation = registry.inspect(
        target_type="ip",
        target="203.0.113.77",
    )

    assert observation.protected_target is True


def test_allowlisted_account_is_normalized():
    registry = (
        StaticTargetProtectionRegistry(
            allowlisted_accounts=[
                "Domain-Admin",
            ],
        )
    )

    observation = registry.inspect(
        target_type="account",
        target=" domain-admin ",
    )

    assert observation.allowlisted_target is True


def test_invalid_configured_ip_rule_is_rejected():
    with pytest.raises(
        ValueError,
        match="IP protection",
    ):
        StaticTargetProtectionRegistry(
            protected_ips=[
                "not-an-ip",
            ],
        )


def test_action_risk_context_uses_same_registry():
    registry = (
        StaticTargetProtectionRegistry(
            protected_ips=[
                "203.0.113.10",
            ],
        )
    )

    provider = (
        make_action_risk_context_provider(
            registry
        )
    )

    state = {
        "alert": SimpleNamespace(
            metadata={}
        )
    }

    context = provider(
        make_action(),
        state,
    )

    assert context.protected_target is True
    assert context.allowlisted_target is False


def test_registry_builds_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "ATHENASEC_PROTECTED_IPS",
        "203.0.113.0/24,198.51.100.10",
    )

    monkeypatch.setenv(
        "ATHENASEC_ALLOWLISTED_ACCOUNTS",
        "root,backup-admin",
    )

    registry = (
        build_target_protection_registry_from_env()
    )

    assert (
        registry.inspect(
            target_type="ip",
            target="203.0.113.10",
        ).protected_target
        is True
    )

    assert (
        registry.inspect(
            target_type="account",
            target="ROOT",
        ).allowlisted_target
        is True
    )


def test_live_registry_reads_updated_store_each_time():
    store = (
        InMemoryTargetProtectionStore()
    )

    initialize_target_protection_store_from_env(
        store
    )

    registry = (
        PersistentTargetProtectionRegistry(
            store
        )
    )

    manager = TargetProtectionManager(
        store=store,
        clock=lambda: FIXED_TIME,
    )

    before = registry.inspect(
        target_type="ip",
        target="203.0.113.10",
    )

    assert before.protected_target is False

    manager.replace(
        protected_ips=[
            "203.0.113.10",
        ],
        changed_by="analyst-001",
        reason="Protect infrastructure.",
    )

    after = registry.inspect(
        target_type="ip",
        target="203.0.113.10",
    )

    assert after.protected_target is True


def test_sqlite_registry_sees_other_worker_update(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(
        "ATHENASEC_PROTECTED_IPS",
        raising=False,
    )

    database_path = (
        tmp_path
        / "target-protection.db"
    )

    writer_store = (
        SQLiteTargetProtectionStore(
            database_path
        )
    )

    reader_store = (
        SQLiteTargetProtectionStore(
            database_path
        )
    )

    initialize_target_protection_store_from_env(
        writer_store
    )

    registry = (
        PersistentTargetProtectionRegistry(
            reader_store
        )
    )

    manager = TargetProtectionManager(
        store=writer_store,
        clock=lambda: FIXED_TIME,
    )

    assert (
        registry.inspect(
            target_type="ip",
            target="203.0.113.10",
        ).protected_target
        is False
    )

    manager.replace(
        protected_ips=[
            "203.0.113.10",
        ],
        changed_by="analyst-001",
        reason="Protect infrastructure.",
    )

    assert (
        registry.inspect(
            target_type="ip",
            target="203.0.113.10",
        ).protected_target
        is True
    )


def test_environment_bootstrap_does_not_overwrite_persisted_change(
    tmp_path,
    monkeypatch,
):
    database_path = (
        tmp_path
        / "target-protection.db"
    )

    monkeypatch.setenv(
        "ATHENASEC_PROTECTED_IPS",
        "198.51.100.10",
    )

    store = SQLiteTargetProtectionStore(
        database_path
    )

    initialize_target_protection_store_from_env(
        store
    )

    manager = TargetProtectionManager(
        store=store,
        clock=lambda: FIXED_TIME,
    )

    manager.replace(
        protected_ips=[
            "203.0.113.10",
        ],
        changed_by="analyst-001",
        reason="Replace protected target.",
    )

    restarted = (
        SQLiteTargetProtectionStore(
            database_path
        )
    )

    initialize_target_protection_store_from_env(
        restarted
    )

    snapshot = restarted.get_snapshot()

    assert snapshot is not None
    assert snapshot.version == 1

    assert snapshot.protected_ips == (
        "203.0.113.10/32",
    )

    assert len(
        restarted.list_changes()
    ) == 1


def test_postgres_target_protection_store_initializes_tables():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresTargetProtectionStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "CREATE TABLE IF NOT EXISTS"
        in executed_sql
    )

    assert (
        "target_protection_state"
        in executed_sql
    )

    assert (
        "target_protection_changes"
        in executed_sql
    )


def test_postgres_target_protection_update_locks_and_guards_version():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresTargetProtectionStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    select_result = MagicMock()

    select_result.fetchone.return_value = (
        0,
    )

    insert_result = MagicMock()

    update_result = MagicMock()
    update_result.rowcount = 1

    connection.execute.side_effect = [
        select_result,
        insert_result,
        update_result,
    ]

    snapshot = (
        build_target_protection_snapshot(
            version=1,
            protected_ips=[
                "203.0.113.10",
            ],
        )
    )

    result = store.apply_update(
        snapshot,
        expected_version=0,
        change_id="TPROT-TEST-001",
        changed_at=FIXED_TIME,
        changed_by="analyst-001",
        reason="Protect infrastructure.",
    )

    assert result == snapshot

    calls = (
        connection
        .execute
        .call_args_list
    )

    assert len(calls) == 3

    select_sql = calls[0].args[0]

    assert "SELECT version" in select_sql
    assert "FOR UPDATE" in select_sql

    insert_sql = calls[1].args[0]

    assert (
        "target_protection_changes"
        in insert_sql
    )

    update_sql = calls[2].args[0]

    assert (
        "UPDATE target_protection_state"
        in update_sql
    )

    assert (
        "AND version = %s"
        in update_sql
    )
