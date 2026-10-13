from datetime import (
    datetime,
    timezone,
)
from unittest.mock import MagicMock

import pytest

from app.schemas import (
    RuntimeControlChangeRecord,
    RuntimeControlStateRecord,
)
from app.services.runtime_control import (
    RuntimeControlManager,
)
from app.services.runtime_control_store import (
    InMemoryRuntimeControlStore,
    PostgresRuntimeControlStore,
    SQLiteRuntimeControlStore,
)


FIXED_TIME = datetime(
    2026,
    10,
    9,
    15,
    0,
    tzinfo=timezone.utc,
)


def test_runtime_control_initializes_supervised():
    store = InMemoryRuntimeControlStore()

    manager = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    state = manager.snapshot()

    assert state.response_mode == "SUPERVISED"

    assert (
        state.operator_execution_enabled
        is True
    )

    assert state.version == 0


def test_runtime_control_update_is_persisted_and_audited():
    store = InMemoryRuntimeControlStore()

    manager = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    state, change = manager.update(
        response_mode="SHADOW",
        operator_execution_enabled=False,
        changed_by="analyst-001",
        reason="Emergency containment review.",
    )

    assert state.response_mode == "SHADOW"

    assert (
        state.operator_execution_enabled
        is False
    )

    assert state.version == 1

    assert (
        change.previous_response_mode
        == "SUPERVISED"
    )

    assert (
        change.new_response_mode
        == "SHADOW"
    )

    assert len(
        store.list_changes()
    ) == 1


def test_runtime_control_state_survives_manager_restart():
    store = InMemoryRuntimeControlStore()

    first = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    first.update(
        response_mode="SHADOW",
        changed_by="analyst-001",
        reason="Enter shadow mode.",
    )

    second = RuntimeControlManager(
        store=store,
        initial_response_mode="AUTONOMOUS",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    state = second.snapshot()

    assert state.response_mode == "SHADOW"

    assert state.version == 1


def test_runtime_control_rejects_empty_update():
    store = InMemoryRuntimeControlStore()

    manager = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        manager.update(
            changed_by="analyst-001",
            reason="No change.",
        )


def test_shadow_cannot_jump_directly_to_autonomous():
    store = InMemoryRuntimeControlStore()

    manager = RuntimeControlManager(
        store=store,
        initial_response_mode="SHADOW",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    with pytest.raises(
        ValueError,
        match="SUPERVISED",
    ):
        manager.update(
            response_mode="AUTONOMOUS",
            changed_by="analyst-001",
            reason="Unsafe escalation.",
        )


def test_sqlite_runtime_control_state_and_history_persist(
    tmp_path,
):
    database_path = (
        tmp_path
        / "runtime-controls.db"
    )

    store = SQLiteRuntimeControlStore(
        database_path
    )

    manager = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    manager.update(
        response_mode="SHADOW",
        operator_execution_enabled=False,
        changed_by="analyst-001",
        reason="Test persisted control.",
    )

    reopened = SQLiteRuntimeControlStore(
        database_path
    )

    state = reopened.get_state()

    assert state is not None

    assert state.response_mode == "SHADOW"

    assert (
        state.operator_execution_enabled
        is False
    )

    assert len(
        reopened.list_changes()
    ) == 1


def test_postgres_runtime_control_store_initializes_tables():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresRuntimeControlStore(
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
        "CREATE TABLE IF NOT EXISTS runtime_control_state"
        in executed_sql
    )

    assert (
        "CREATE TABLE IF NOT EXISTS runtime_control_changes"
        in executed_sql
    )


def test_postgres_runtime_update_writes_history_and_snapshot():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresRuntimeControlStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    state = RuntimeControlStateRecord(
        response_mode="SHADOW",
        operator_execution_enabled=False,
        version=1,
        updated_at=FIXED_TIME,
        updated_by="analyst-001",
        update_reason="Emergency review.",
    )

    change = RuntimeControlChangeRecord(
        change_id="RCTRL-CHANGE-001",
        version=1,
        previous_response_mode="SUPERVISED",
        new_response_mode="SHADOW",
        previous_operator_execution_enabled=True,
        new_operator_execution_enabled=False,
        changed_at=FIXED_TIME,
        changed_by="analyst-001",
        reason="Emergency review.",
    )

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

    result = store.apply_update(
        state,
        change,
        expected_version=0,
    )

    assert result == state

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "INSERT INTO runtime_control_changes"
        in executed_sql
    )

    assert (
        "UPDATE runtime_control_state"
        in executed_sql
    )

    assert (
        "AND version = %s"
        in executed_sql
    )


def test_manager_refreshes_persisted_version_before_update():
    store = InMemoryRuntimeControlStore()

    first = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    second = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    first_state, _ = first.update(
        response_mode="SHADOW",
        changed_by="analyst-001",
        reason="Enter shadow mode.",
    )

    assert first_state.version == 1

    second_state, _ = second.update(
        operator_execution_enabled=False,
        changed_by="analyst-002",
        reason="Disable execution.",
    )

    assert second_state.version == 2

    assert (
        second_state.response_mode
        == "SHADOW"
    )

    assert (
        second_state.operator_execution_enabled
        is False
    )

    assert len(
        store.list_changes()
    ) == 2


def test_sqlite_runtime_control_rejects_stale_expected_version(
    tmp_path,
):
    database_path = (
        tmp_path
        / "runtime-control-concurrency.db"
    )

    store = SQLiteRuntimeControlStore(
        database_path
    )

    initial = RuntimeControlStateRecord(
        response_mode="SUPERVISED",
        operator_execution_enabled=True,
        version=0,
        updated_at=FIXED_TIME,
        updated_by="system-startup",
        update_reason="Initial state.",
    )

    store.initialize_state(
        initial
    )

    version_one = (
        RuntimeControlStateRecord(
            response_mode="SHADOW",
            operator_execution_enabled=True,
            version=1,
            updated_at=FIXED_TIME,
            updated_by="analyst-001",
            update_reason="First update.",
        )
    )

    first_change = (
        RuntimeControlChangeRecord(
            change_id="RCTRL-FIRST",
            version=1,
            previous_response_mode=(
                "SUPERVISED"
            ),
            new_response_mode="SHADOW",
            previous_operator_execution_enabled=True,
            new_operator_execution_enabled=True,
            changed_at=FIXED_TIME,
            changed_by="analyst-001",
            reason="First update.",
        )
    )

    store.apply_update(
        version_one,
        first_change,
        expected_version=0,
    )

    stale_version_one = (
        RuntimeControlStateRecord(
            response_mode="SUPERVISED",
            operator_execution_enabled=False,
            version=1,
            updated_at=FIXED_TIME,
            updated_by="analyst-002",
            update_reason="Stale update.",
        )
    )

    stale_change = (
        RuntimeControlChangeRecord(
            change_id="RCTRL-STALE",
            version=1,
            previous_response_mode=(
                "SUPERVISED"
            ),
            new_response_mode=(
                "SUPERVISED"
            ),
            previous_operator_execution_enabled=True,
            new_operator_execution_enabled=False,
            changed_at=FIXED_TIME,
            changed_by="analyst-002",
            reason="Stale update.",
        )
    )

    with pytest.raises(
        ValueError,
        match="concurrently",
    ):
        store.apply_update(
            stale_version_one,
            stale_change,
            expected_version=0,
        )

    current = store.get_state()

    assert current is not None

    assert current.version == 1

    assert (
        current.response_mode
        == "SHADOW"
    )

    assert len(
        store.list_changes()
    ) == 1


def test_postgres_runtime_update_locks_expected_version():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresRuntimeControlStore(
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

    state = RuntimeControlStateRecord(
        response_mode="SHADOW",
        operator_execution_enabled=False,
        version=1,
        updated_at=FIXED_TIME,
        updated_by="analyst-001",
        update_reason="Concurrent-safe update.",
    )

    change = RuntimeControlChangeRecord(
        change_id="RCTRL-CONCURRENT-001",
        version=1,
        previous_response_mode="SUPERVISED",
        new_response_mode="SHADOW",
        previous_operator_execution_enabled=True,
        new_operator_execution_enabled=False,
        changed_at=FIXED_TIME,
        changed_by="analyst-001",
        reason="Concurrent-safe update.",
    )

    result = store.apply_update(
        state,
        change,
        expected_version=0,
    )

    assert result == state

    calls = (
        connection
        .execute
        .call_args_list
    )

    assert len(calls) == 3

    select_sql = calls[0].args[0]

    assert (
        "SELECT version"
        in select_sql
    )

    assert (
        "FOR UPDATE"
        in select_sql
    )

    update_sql = calls[2].args[0]

    assert (
        "UPDATE runtime_control_state"
        in update_sql
    )

    assert (
        "version = %s"
        in update_sql
    )


def test_manager_snapshot_refreshes_external_store_update():
    store = InMemoryRuntimeControlStore()

    first = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    second = RuntimeControlManager(
        store=store,
        initial_response_mode="SUPERVISED",
        initial_operator_execution_enabled=True,
        clock=lambda: FIXED_TIME,
    )

    first.update(
        response_mode="SHADOW",
        changed_by="analyst-001",
        reason="Enter shadow mode.",
    )

    observed = second.snapshot()

    assert observed.version == 1

    assert (
        observed.response_mode
        == "SHADOW"
    )
