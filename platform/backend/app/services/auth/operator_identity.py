"""Backend-verified, per-operator approval credentials (interim M8 gate).

This is NOT frontend authentication. No human API tokens may be placed in React.
The operator-control key never authorizes an individual human approval.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

import psycopg


@dataclass(frozen=True)
class OperatorIdentity:
    operator_id: str
    can_read_approvals: bool
    can_decide_approvals: bool


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return "aso_" + secrets.token_urlsafe(40)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class OperatorIdentityStore(Protocol):
    def resolve(self, token: str) -> OperatorIdentity | None: ...


class InMemoryOperatorIdentityStore:
    """Test-only store. Production credentials MUST be persisted in PostgreSQL."""

    def __init__(self):
        self._records: dict[str, tuple[OperatorIdentity, datetime, bool]] = {}

    def provision(self, *, operator_id: str, can_read: bool = True,
                  can_approve: bool = False, ttl_hours: int = 8) -> str:
        if not operator_id.strip() or not 1 <= ttl_hours <= 24:
            raise ValueError("Invalid operator identity or credential lifetime")
        token = _new_token()
        self._records[_digest(token)] = (
            OperatorIdentity(operator_id, can_read or can_approve, can_approve),
            _now() + timedelta(hours=ttl_hours), True,
        )
        return token

    def revoke(self, token: str) -> None:
        key = _digest(token)
        if key in self._records:
            identity, expiry, _ = self._records[key]
            self._records[key] = (identity, expiry, False)

    def resolve(self, token: str) -> OperatorIdentity | None:
        if not token.startswith("aso_"):
            return None
        record = self._records.get(_digest(token))
        if record is None:
            return None
        identity, expiry, active = record
        if not active or _now() >= expiry:
            return None
        return identity


class PostgresOperatorIdentityStore:
    """PostgreSQL-backed operator credentials; stores SHA-256 digests only.

    Credentials must be individually issued and securely distributed outside
    the browser; these are not replacements for MFA-backed user sessions.
    """

    def __init__(self, database_url: str):
        self.database_url = database_url
        with psycopg.connect(database_url) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_operator_identities (
                    operator_id TEXT PRIMARY KEY,
                    can_read_approvals BOOLEAN NOT NULL,
                    can_decide_approvals BOOLEAN NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_operator_credentials (
                    token_digest TEXT PRIMARY KEY,
                    operator_id TEXT NOT NULL REFERENCES athenasec_operator_identities(operator_id),
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)

    def provision(self, *, operator_id: str, can_read: bool = True,
                  can_approve: bool = False, ttl_hours: int = 8) -> str:
        operator_id = operator_id.strip()
        if not operator_id or not 1 <= ttl_hours <= 24:
            raise ValueError("Invalid operator identity or credential lifetime")
        token = _new_token()
        with psycopg.connect(self.database_url) as connection:
            connection.execute("""
                INSERT INTO athenasec_operator_identities
                (operator_id, can_read_approvals, can_decide_approvals, active)
                VALUES (%s, %s, %s, TRUE)
                ON CONFLICT (operator_id) DO UPDATE SET
                    can_read_approvals = EXCLUDED.can_read_approvals,
                    can_decide_approvals = EXCLUDED.can_decide_approvals,
                    active = TRUE
            """, (operator_id, can_read or can_approve, can_approve))
            # Prior credentials must not silently survive re-provisioning.
            connection.execute("""
                UPDATE athenasec_operator_credentials
                SET revoked = TRUE WHERE operator_id = %s
            """, (operator_id,))
            connection.execute("""
                INSERT INTO athenasec_operator_credentials
                (token_digest, operator_id, expires_at)
                VALUES (%s, %s, %s)
            """, (_digest(token), operator_id, _now() + timedelta(hours=ttl_hours)))
        return token

    def disable(self, operator_id: str) -> None:
        with psycopg.connect(self.database_url) as connection:
            connection.execute("""
                UPDATE athenasec_operator_identities SET active=FALSE
                WHERE operator_id=%s
            """, (operator_id,))
            connection.execute("""
                UPDATE athenasec_operator_credentials SET revoked=TRUE
                WHERE operator_id=%s
            """, (operator_id,))

    def resolve(self, token: str) -> OperatorIdentity | None:
        if not token.startswith("aso_"):
            return None
        with psycopg.connect(self.database_url) as connection:
            row = connection.execute("""
                SELECT u.operator_id, u.can_read_approvals,
                       u.can_decide_approvals
                FROM athenasec_operator_credentials AS c
                JOIN athenasec_operator_identities AS u
                  ON u.operator_id = c.operator_id
                WHERE c.token_digest=%s AND NOT c.revoked
                  AND c.expires_at > CURRENT_TIMESTAMP AND u.active
            """, (_digest(token),)).fetchone()
        return OperatorIdentity(*row) if row else None


def build_operator_identity_store_from_env() -> OperatorIdentityStore | None:
    # Deliberately fail closed when no PostgreSQL backing exists.
    if os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").lower() != "postgres":
        return None
    database_url = os.getenv("ATHENASEC_DATABASE_URL")
    return PostgresOperatorIdentityStore(database_url) if database_url else None


def _cli() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Provision/revoke AthenaSec operator tokens")
    sub = parser.add_subparsers(dest="command", required=True)
    provision = sub.add_parser("provision")
    provision.add_argument("operator_id")
    provision.add_argument("--approver", action="store_true")
    provision.add_argument("--ttl-hours", type=int, default=8)
    disable = sub.add_parser("disable")
    disable.add_argument("operator_id")
    args = parser.parse_args()
    store = build_operator_identity_store_from_env()
    if not isinstance(store, PostgresOperatorIdentityStore):
        parser.error("PostgreSQL ATHENASEC_DATABASE_URL must be configured")
    if args.command == "disable":
        store.disable(args.operator_id)
        print("Operator disabled and credentials revoked")
    else:
        token = store.provision(
            operator_id=args.operator_id,
            can_approve=args.approver,
            ttl_hours=args.ttl_hours,
        )
        print("Provisioned operator. One-time credential (keep private):")
        print(token)


if __name__ == "__main__":
    _cli()
