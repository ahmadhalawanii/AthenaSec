import os
import threading
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
from app.services.execution.target_operation_coordinator import (
    InMemoryTargetOperationCoordinator,
    PostgresTargetOperationCoordinator,
)
from app.services.containment.containment_expiry_runner import (
    execution_enabled,
    run_expiry_cycle,
)


def test_same_ip_is_serialized_across_threads():
    coordinator = InMemoryTargetOperationCoordinator()
    entered = threading.Event()
    attempting = threading.Event()

    def contender():
        attempting.set()
        with coordinator.hold("203.0.113.10"):
            entered.set()

    with coordinator.hold("203.0.113.10"):
        thread = threading.Thread(target=contender)
        thread.start()
        assert attempting.wait(timeout=2)
        assert not entered.wait(timeout=0.1)
    assert entered.wait(timeout=2)
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_distinct_ips_are_not_serialized_in_memory():
    coordinator = InMemoryTargetOperationCoordinator()
    entered = threading.Event()

    def contender():
        with coordinator.hold("203.0.113.11"):
            entered.set()

    with coordinator.hold("203.0.113.10"):
        thread = threading.Thread(target=contender)
        thread.start()
        assert entered.wait(timeout=2)
    thread.join(timeout=2)


def test_live_control_is_fail_closed():
    store = SimpleNamespace(get_state=lambda: None)
    assert execution_enabled(True, store) is False
    store.get_state = lambda: SimpleNamespace(
        operator_execution_enabled=False,
        response_mode="AUTONOMOUS",
    )
    assert execution_enabled(True, store) is False
    store.get_state = lambda: SimpleNamespace(
        operator_execution_enabled=True,
        response_mode="SHADOW",
    )
    assert execution_enabled(True, store) is False
    store.get_state = lambda: SimpleNamespace(
        operator_execution_enabled=True,
        response_mode="SUPERVISED",
    )
    assert execution_enabled(False, store) is False
    assert execution_enabled(True, store) is True


def test_structured_response_guard_holds_target_lock():
    from app.services.response.structured_response_runtime import _coordinate_block_response
    from app.services.execution.target_operation_coordinator import InMemoryTargetOperationCoordinator

    coordinator = InMemoryTargetOperationCoordinator()
    action = SimpleNamespace(action_type="block_ip", target="203.0.113.10")
    entered = []

    @_coordinate_block_response
    def fake_response(*, proposed_action, target_coordinator):
        entered.append(proposed_action.target)
        return "executed"

    assert fake_response(
        proposed_action=action,
        target_coordinator=coordinator,
    ) == "executed"
    assert entered == ["203.0.113.10"]


def test_pg_advisory_lock_uses_transaction_and_normalizes_address():
    from unittest.mock import MagicMock
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.transaction.return_value.__enter__.return_value = None
    connect = MagicMock(return_value=connection)
    coordinator = PostgresTargetOperationCoordinator(
        "postgresql://test", connect=connect
    )
    with coordinator.hold("2001:0db8::0001"):
        pass
    sql, params = connection.execute.call_args.args
    assert "pg_advisory_xact_lock" in sql
    assert params[0] == "athenasec:ip-operation:2001:db8::1"
    assert connection.transaction.called


@pytest.mark.skipif(
    not os.getenv("ATHENASEC_TEST_PG_URL"),
    reason="Set ATHENASEC_TEST_PG_URL for real PostgreSQL concurrency test",
)
def test_real_postgres_advisory_lock_serializes_workers():
    import time
    dsn = os.environ["ATHENASEC_TEST_PG_URL"]
    first = PostgresTargetOperationCoordinator(dsn)
    second = PostgresTargetOperationCoordinator(dsn)
    attempting = threading.Event()
    entered = threading.Event()

    def contender():
        attempting.set()
        with second.hold("203.0.113.10"):
            entered.set()

    with first.hold("203.0.113.10"):
        thread = threading.Thread(target=contender)
        thread.start()
        assert attempting.wait(2)
        assert not entered.wait(0.25)
    assert entered.wait(5)
    thread.join(5)
    assert not thread.is_alive()
