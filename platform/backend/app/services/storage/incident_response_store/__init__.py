"""Incident response storage.

Where AthenaSec keeps incident risk scores, proposed actions, approvals,
executed actions, verifications, rollbacks and incident cases.

Files in this folder:
    base.py      the interface every store follows + shared approval rules
    memory.py    in-memory store (tests, demos)
    sqlite.py    SQLite store (local .db file)
    postgres.py  PostgreSQL store (Docker / production)
"""

from app.services.storage.incident_response_store.base import IncidentResponseStore
from app.services.storage.incident_response_store.memory import InMemoryIncidentResponseStore
from app.services.storage.incident_response_store.postgres import PostgresIncidentResponseStore
from app.services.storage.incident_response_store.sqlite import SQLiteIncidentResponseStore

__all__ = [
    "IncidentResponseStore",
    "InMemoryIncidentResponseStore",
    "PostgresIncidentResponseStore",
    "SQLiteIncidentResponseStore",
]
