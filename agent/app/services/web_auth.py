"""AthenaSec browser authentication backed by PostgreSQL.

Requires ATHENASEC_DATABASE_URL and ATHENASEC_TOTP_MASTER_KEY (64 hex chars).
Opaque httpOnly session cookies. One-time MFA TOTP counters. No demo accounts.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import psycopg


SESSION_COOKIE_NAME = "athenasec_session"
PASSWORD_ITERATIONS = 600_000
DUMMY_SALT = b"athenasec-password-dummy-salt"


@dataclass(frozen=True)
class BrowserPrincipal:
    user_id: str
    email: str
    name: str
    role: str
    can_read_approvals: bool
    can_decide_approvals: bool
    csrf_token: str

    @property
    def operator_id(self) -> str:
        return self.user_id

    def public_user(self) -> dict[str, str]:
        return {"email": self.email, "name": self.name, "role": self.role}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)


def _totp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset: offset + 4])[0] & 0x7fffffff) % 1_000_000
    return f"{value:06d}"


def _totp_counter(secret: bytes, code: str, last_counter: int, now: datetime) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now.timestamp() // 30)
    for counter in (current - 1, current, current + 1):
        if counter > last_counter and hmac.compare_digest(_totp(secret, counter), code):
            return counter
    return None


def _master_key_from_env() -> bytes | None:
    key = os.getenv("ATHENASEC_TOTP_MASTER_KEY", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        return None
    return bytes.fromhex(key)


class InvalidCredentials(ValueError):
    pass


class PostgresBrowserAuthStore:
    def __init__(self, database_url: str, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("MFA master key must be 32 bytes")
        self.database_url = database_url
        self._master_key = master_key
        with psycopg.connect(database_url) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_web_users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('Analyst','Administrator')),
                    password_salt BYTEA NOT NULL,
                    password_digest BYTEA NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    can_read_approvals BOOLEAN NOT NULL DEFAULT FALSE,
                    can_decide_approvals BOOLEAN NOT NULL DEFAULT FALSE,
                    failures INTEGER NOT NULL DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    last_totp_counter BIGINT NOT NULL DEFAULT -1
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_web_challenges (
                    challenge_digest TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES athenasec_web_users(user_id),
                    expires_at TIMESTAMPTZ NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_web_sessions (
                    session_digest TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES athenasec_web_users(user_id),
                    csrf_token TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS athenasec_web_auth_events (
                    event_id BIGSERIAL PRIMARY KEY,
                    user_id TEXT,
                    event_type TEXT NOT NULL,
                    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

    @staticmethod
    def _event(connection, user_id: str | None, event_type: str) -> None:
        connection.execute("""
            INSERT INTO athenasec_web_auth_events (user_id,event_type)
            VALUES (%s,%s)
        """, (user_id, event_type))

    def _secret(self, user_id: str) -> bytes:
        return hmac.new(self._master_key, b"athenasec-totp-v1:" + user_id.encode(), hashlib.sha256).digest()[:20]

    def provision_user(self, *, user_id: str, email: str, name: str, password: str,
                       role: str, can_read: bool = False, can_approve: bool = False) -> str:
        user_id, email, name = user_id.strip(), email.strip().casefold(), name.strip()
        if (not user_id or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
                or not name or role not in {"Analyst", "Administrator"}
                or len(password) < 14 or len(password) > 1024):
            raise ValueError("Invalid account fields or password (minimum 14 characters)")
        salt = secrets.token_bytes(16)
        with psycopg.connect(self.database_url) as connection:
            connection.execute("""
                INSERT INTO athenasec_web_users
                (user_id,email,display_name,role,password_salt,password_digest,
                 can_read_approvals,can_decide_approvals)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (user_id, email, name, role, salt, _password_hash(password, salt),
                  can_read or can_approve, can_approve))
            self._event(connection, user_id, "user_created")
        key = base64.b32encode(self._secret(user_id)).decode("ascii").rstrip("=")
        return "otpauth://totp/" + quote("AthenaSec:" + email, safe="") + "?secret=" + key + "&issuer=AthenaSec"

    def disable_user(self, user_id: str) -> None:
        with psycopg.connect(self.database_url) as connection:
            connection.execute("UPDATE athenasec_web_users SET active=FALSE WHERE user_id=%s", (user_id,))
            connection.execute("UPDATE athenasec_web_sessions SET revoked=TRUE WHERE user_id=%s", (user_id,))
            connection.execute("DELETE FROM athenasec_web_challenges WHERE user_id=%s", (user_id,))
            self._event(connection, user_id, "user_disabled")

    def begin_login(self, email: str, password: str) -> str:
        if len(email) > 254 or len(password) > 1024:
            raise InvalidCredentials("Invalid email or password")
        now = _now()
        with psycopg.connect(self.database_url) as connection:
            row = connection.execute("""
                SELECT user_id, password_salt, password_digest, active, failures, locked_until
                FROM athenasec_web_users WHERE email=%s FOR UPDATE
            """, (email.strip().casefold(),)).fetchone()
            if not row:
                _password_hash(password, DUMMY_SALT)
                self._event(connection, None, "login_rejected")
                invalid_user = True
            else:
                invalid_user = False
            if invalid_user:
                # Commit the audit record before signaling failure.
                error = True
                user_id = None
            else:
                user_id, salt, expected, active, failures, locked_until = row
            if not invalid_user:
                valid = hmac.compare_digest(_password_hash(password, bytes(salt)), bytes(expected))
            if not invalid_user and (not active or (locked_until is not None and locked_until > now) or not valid):
                if active and (locked_until is None or locked_until <= now):
                    failures += 1
                    lockout = now + timedelta(minutes=15) if failures >= 5 else None
                    connection.execute("""
                        UPDATE athenasec_web_users SET failures=%s, locked_until=%s
                        WHERE user_id=%s
                    """, (failures, lockout, user_id))
                self._event(connection, user_id, "login_rejected")
                # Commit failed-attempt bookkeeping before raising outside context manager.
                error = True
            elif not invalid_user:
                error = False
                connection.execute("DELETE FROM athenasec_web_challenges WHERE user_id=%s", (user_id,))
                self._event(connection, user_id, "password_accepted")
                challenge = secrets.token_urlsafe(40)
                connection.execute("""
                    INSERT INTO athenasec_web_challenges
                    (challenge_digest,user_id,expires_at) VALUES (%s,%s,%s)
                """, (_digest(challenge), user_id, now + timedelta(minutes=5)))
        if error:
            raise InvalidCredentials("Invalid email or password")
        return challenge

    def complete_mfa(self, challenge: str, code: str) -> tuple[str, BrowserPrincipal]:
        if len(challenge) < 30 or len(challenge) > 200:
            raise InvalidCredentials("Invalid or expired authentication challenge")
        now = _now()
        with psycopg.connect(self.database_url) as connection:
            record = connection.execute("""
                SELECT user_id, expires_at, attempts FROM athenasec_web_challenges
                WHERE challenge_digest=%s FOR UPDATE
            """, (_digest(challenge),)).fetchone()
            if not record:
                raise InvalidCredentials("Invalid or expired authentication challenge")
            user_id, expires_at, attempts = record
            user = connection.execute("""
                SELECT email,display_name,role,active,can_read_approvals,
                       can_decide_approvals,last_totp_counter,locked_until,failures
                FROM athenasec_web_users WHERE user_id=%s FOR UPDATE
            """, (user_id,)).fetchone()
            if (not user or not user[3] or now >= expires_at or attempts >= 5
                    or (user[7] is not None and user[7] > now)):
                connection.execute("DELETE FROM athenasec_web_challenges WHERE challenge_digest=%s", (_digest(challenge),))
                self._event(connection, user_id, "mfa_rejected")
                invalid = True
            else:
                next_counter = _totp_counter(self._secret(user_id), code, user[6], now)
                if next_counter is None:
                    connection.execute("""
                        UPDATE athenasec_web_challenges SET attempts=attempts+1
                        WHERE challenge_digest=%s
                    """, (_digest(challenge),))
                    failures = user[8] + 1
                    lockout = now + timedelta(minutes=15) if failures >= 5 else None
                    connection.execute("""
                        UPDATE athenasec_web_users SET failures=%s, locked_until=%s
                        WHERE user_id=%s
                    """, (failures, lockout, user_id))
                    self._event(connection, user_id, "mfa_rejected")
                    invalid = True
                else:
                    invalid = False
                    connection.execute("""
                        UPDATE athenasec_web_users
                        SET last_totp_counter=%s, failures=0, locked_until=NULL
                        WHERE user_id=%s
                    """, (next_counter, user_id))
                    connection.execute("DELETE FROM athenasec_web_challenges WHERE user_id=%s", (user_id,))
                    session = secrets.token_urlsafe(48)
                    csrf_token = secrets.token_urlsafe(32)
                    connection.execute("""
                        INSERT INTO athenasec_web_sessions
                        (session_digest,user_id,csrf_token,expires_at)
                        VALUES (%s,%s,%s,%s)
                    """, (_digest(session), user_id, csrf_token, now + timedelta(hours=8)))
                    principal = BrowserPrincipal(user_id, user[0], user[1], user[2],
                                                 user[4], user[5], csrf_token)
                    self._event(connection, user_id, "mfa_verified_session_started")
        if invalid:
            raise InvalidCredentials("Invalid or expired authentication challenge")
        return session, principal

    def resolve_session(self, session: str | None) -> BrowserPrincipal | None:
        if not session or len(session) > 200:
            return None
        with psycopg.connect(self.database_url) as connection:
            row = connection.execute("""
                SELECT u.user_id,u.email,u.display_name,u.role,
                       u.can_read_approvals,u.can_decide_approvals,s.csrf_token
                FROM athenasec_web_sessions s
                JOIN athenasec_web_users u ON s.user_id=u.user_id
                WHERE s.session_digest=%s AND s.expires_at>CURRENT_TIMESTAMP
                  AND NOT s.revoked AND u.active
            """, (_digest(session),)).fetchone()
        return BrowserPrincipal(*row) if row else None

    def revoke_session(self, session: str) -> None:
        with psycopg.connect(self.database_url) as connection:
            row = connection.execute("""
                UPDATE athenasec_web_sessions SET revoked=TRUE
                WHERE session_digest=%s AND NOT revoked RETURNING user_id
            """, (_digest(session),)).fetchone()
            if row:
                self._event(connection, row[0], "session_revoked")


def build_browser_auth_store_from_env() -> PostgresBrowserAuthStore | None:
    if os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower() != "postgres":
        return None
    url = os.getenv("ATHENASEC_DATABASE_URL")
    master = _master_key_from_env()
    return PostgresBrowserAuthStore(url, master) if url and master else None


def _cli() -> None:
    parser = argparse.ArgumentParser(description="AthenaSec real browser account administration")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("user_id")
    create.add_argument("email")
    create.add_argument("name")
    create.add_argument("--role", choices=["Analyst", "Administrator"], default="Analyst")
    create.add_argument("--approver", action="store_true")
    disable = sub.add_parser("disable")
    disable.add_argument("user_id")
    args = parser.parse_args()
    store = build_browser_auth_store_from_env()
    if store is None:
        parser.error("PostgreSQL ATHENASEC_DATABASE_URL and 64-hex ATHENASEC_TOTP_MASTER_KEY required")
    if args.command == "disable":
        store.disable_user(args.user_id)
        print("Account disabled and browser sessions revoked")
    else:
        password = getpass.getpass("New password (14+ characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            parser.error("Passwords do not match")
        uri = store.provision_user(user_id=args.user_id, email=args.email,
                                   name=args.name, password=password, role=args.role,
                                   can_approve=args.approver, can_read=True)
        print("Account created. Enroll authenticator with this one-time TOTP URI.")
        print("Keep this URI private; it contains the user's MFA secret.")
        print(uri)


if __name__ == "__main__":
    _cli()
