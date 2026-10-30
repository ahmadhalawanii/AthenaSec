"""Serialize IP block/unblock operations across backend processes.

PostgreSQL holds a transaction-level advisory lock on a dedicated connection
for the *whole* Cortex operation. All block/unblock paths MUST use the same
coordinator. InMemory is single-process and is only suitable for testing.
"""
import ipaddress
from contextlib import contextmanager
from threading import Lock, RLock
from typing import Protocol

import psycopg


def normalize_ip(value: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Coordination target must be a valid IP address.")
    return str(ipaddress.ip_address(value))


class TargetOperationCoordinator(Protocol):
    def hold(self, target: str): ...


class InMemoryTargetOperationCoordinator:
    """Serializes operations within one Python process only."""

    def __init__(self):
        self._map_lock = Lock()
        self._locks = {}

    @contextmanager
    def hold(self, target: str):
        target = normalize_ip(target)
        with self._map_lock:
            lock = self._locks.setdefault(target, RLock())
        with lock:
            yield


class PostgresTargetOperationCoordinator:
    """Database-wide serialization; do not share a session across threads."""

    def __init__(self, database_url: str, *, connect=None):
        if not database_url:
            raise ValueError("PostgreSQL URL is required for target locks.")
        self.database_url = database_url
        self._connect = connect or psycopg.connect

    @contextmanager
    def hold(self, target: str):
        target = normalize_ip(target)
        key = "athenasec:ip-operation:" + target
        # A dedicated DB transaction remains open during Cortex I/O.
        # If this connection drops, the advisory lock is lost: operational
        # monitoring and reconciliation are still mandatory.
        with self._connect(self.database_url) as connection:
            with connection.transaction():
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (key,),
                )
                yield
