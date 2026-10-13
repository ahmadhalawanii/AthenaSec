import ipaddress
import os
from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from threading import RLock
from typing import Protocol
from uuid import (
    NAMESPACE_URL,
    uuid5,
)


@dataclass(
    frozen=True,
)
class TargetProtectionObservation:
    protected_target: bool
    allowlisted_target: bool


@dataclass(
    frozen=True,
)
class TargetProtectionSnapshot:
    version: int

    protected_ips: tuple[str, ...] = ()
    allowlisted_ips: tuple[str, ...] = ()

    protected_accounts: tuple[str, ...] = ()
    allowlisted_accounts: tuple[str, ...] = ()

    protected_endpoints: tuple[str, ...] = ()
    allowlisted_endpoints: tuple[str, ...] = ()


class TargetProtectionRegistry(
    Protocol
):
    def inspect(
        self,
        *,
        target_type: str,
        target: str,
    ) -> TargetProtectionObservation:
        ...


class TargetProtectionSnapshotStore(
    Protocol
):
    def get_snapshot(
        self,
    ) -> (
        TargetProtectionSnapshot
        | None
    ):
        ...

    def initialize_snapshot(
        self,
        snapshot: TargetProtectionSnapshot,
    ) -> TargetProtectionSnapshot:
        ...

    def apply_update(
        self,
        snapshot: TargetProtectionSnapshot,
        *,
        expected_version: int,
        change_id: str,
        changed_at: datetime,
        changed_by: str,
        reason: str,
    ) -> TargetProtectionSnapshot:
        ...


def _utc_now():
    return datetime.now(
        timezone.utc
    )


def _split_env(
    value: str | None,
) -> list[str]:
    if not value:
        return []

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def _normalize_name(
    value: str,
) -> str:
    return (
        value
        .strip()
        .casefold()
    )


def _normalize_ip_rule(
    value: str,
) -> str:
    candidate = value.strip()

    try:
        if "/" in candidate:
            rule = ipaddress.ip_network(
                candidate,
                strict=False,
            )

        else:
            address = (
                ipaddress.ip_address(
                    candidate
                )
            )

            rule = ipaddress.ip_network(
                (
                    f"{address}/"
                    f"{address.max_prefixlen}"
                ),
                strict=False,
            )

    except ValueError as exc:
        raise ValueError(
            "Invalid IP protection "
            f"rule: {candidate}"
        ) from exc

    return str(
        rule
    )


def _normalize_ip_rules(
    values,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _normalize_ip_rule(
                    value
                )
                for value in values
                if value.strip()
            }
        )
    )


def _normalize_names(
    values,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _normalize_name(
                    value
                )
                for value in values
                if value.strip()
            }
        )
    )


def build_target_protection_snapshot(
    *,
    version: int,
    protected_ips=(),
    allowlisted_ips=(),
    protected_accounts=(),
    allowlisted_accounts=(),
    protected_endpoints=(),
    allowlisted_endpoints=(),
) -> TargetProtectionSnapshot:
    if version < 0:
        raise ValueError(
            "Target protection version "
            "cannot be negative."
        )

    return TargetProtectionSnapshot(
        version=version,
        protected_ips=(
            _normalize_ip_rules(
                protected_ips
            )
        ),
        allowlisted_ips=(
            _normalize_ip_rules(
                allowlisted_ips
            )
        ),
        protected_accounts=(
            _normalize_names(
                protected_accounts
            )
        ),
        allowlisted_accounts=(
            _normalize_names(
                allowlisted_accounts
            )
        ),
        protected_endpoints=(
            _normalize_names(
                protected_endpoints
            )
        ),
        allowlisted_endpoints=(
            _normalize_names(
                allowlisted_endpoints
            )
        ),
    )


def build_target_protection_snapshot_from_env(
    *,
    version: int = 0,
) -> TargetProtectionSnapshot:
    return build_target_protection_snapshot(
        version=version,
        protected_ips=_split_env(
            os.getenv(
                "ATHENASEC_PROTECTED_IPS"
            )
        ),
        allowlisted_ips=_split_env(
            os.getenv(
                "ATHENASEC_ALLOWLISTED_IPS"
            )
        ),
        protected_accounts=_split_env(
            os.getenv(
                "ATHENASEC_PROTECTED_ACCOUNTS"
            )
        ),
        allowlisted_accounts=_split_env(
            os.getenv(
                "ATHENASEC_ALLOWLISTED_ACCOUNTS"
            )
        ),
        protected_endpoints=_split_env(
            os.getenv(
                "ATHENASEC_PROTECTED_ENDPOINTS"
            )
        ),
        allowlisted_endpoints=_split_env(
            os.getenv(
                "ATHENASEC_ALLOWLISTED_ENDPOINTS"
            )
        ),
    )


class StaticTargetProtectionRegistry:
    def __init__(
        self,
        *,
        protected_ips=(),
        allowlisted_ips=(),
        protected_accounts=(),
        allowlisted_accounts=(),
        protected_endpoints=(),
        allowlisted_endpoints=(),
    ):
        snapshot = (
            build_target_protection_snapshot(
                version=0,
                protected_ips=protected_ips,
                allowlisted_ips=allowlisted_ips,
                protected_accounts=(
                    protected_accounts
                ),
                allowlisted_accounts=(
                    allowlisted_accounts
                ),
                protected_endpoints=(
                    protected_endpoints
                ),
                allowlisted_endpoints=(
                    allowlisted_endpoints
                ),
            )
        )

        self._snapshot = snapshot

    def inspect(
        self,
        *,
        target_type: str,
        target: str,
    ) -> TargetProtectionObservation:
        return _inspect_snapshot(
            self._snapshot,
            target_type=target_type,
            target=target,
        )


class PersistentTargetProtectionRegistry:
    def __init__(
        self,
        store: TargetProtectionSnapshotStore,
    ):
        self.store = store

    def inspect(
        self,
        *,
        target_type: str,
        target: str,
    ) -> TargetProtectionObservation:
        snapshot = (
            self.store.get_snapshot()
        )

        if snapshot is None:
            raise RuntimeError(
                "Target protection state "
                "is unavailable."
            )

        return _inspect_snapshot(
            snapshot,
            target_type=target_type,
            target=target,
        )


def _inspect_snapshot(
    snapshot: TargetProtectionSnapshot,
    *,
    target_type: str,
    target: str,
) -> TargetProtectionObservation:
    normalized_type = (
        target_type
        .strip()
        .casefold()
    )

    if normalized_type == "ip":
        try:
            address = (
                ipaddress.ip_address(
                    target.strip()
                )
            )

        except ValueError:
            return TargetProtectionObservation(
                protected_target=False,
                allowlisted_target=False,
            )

        protected = any(
            address
            in ipaddress.ip_network(
                rule,
                strict=False,
            )
            for rule
            in snapshot.protected_ips
        )

        allowlisted = any(
            address
            in ipaddress.ip_network(
                rule,
                strict=False,
            )
            for rule
            in snapshot.allowlisted_ips
        )

    elif normalized_type == "account":
        normalized_target = (
            _normalize_name(
                target
            )
        )

        protected = (
            normalized_target
            in snapshot.protected_accounts
        )

        allowlisted = (
            normalized_target
            in snapshot.allowlisted_accounts
        )

    elif normalized_type == "endpoint":
        normalized_target = (
            _normalize_name(
                target
            )
        )

        protected = (
            normalized_target
            in snapshot.protected_endpoints
        )

        allowlisted = (
            normalized_target
            in snapshot.allowlisted_endpoints
        )

    else:
        protected = False
        allowlisted = False

    return TargetProtectionObservation(
        protected_target=protected,
        allowlisted_target=allowlisted,
    )


def initialize_target_protection_store_from_env(
    store: TargetProtectionSnapshotStore,
) -> TargetProtectionSnapshot:
    initial = (
        build_target_protection_snapshot_from_env(
            version=0
        )
    )

    return store.initialize_snapshot(
        initial
    )


def build_target_protection_registry_from_env():
    snapshot = (
        build_target_protection_snapshot_from_env()
    )

    return StaticTargetProtectionRegistry(
        protected_ips=(
            snapshot.protected_ips
        ),
        allowlisted_ips=(
            snapshot.allowlisted_ips
        ),
        protected_accounts=(
            snapshot.protected_accounts
        ),
        allowlisted_accounts=(
            snapshot.allowlisted_accounts
        ),
        protected_endpoints=(
            snapshot.protected_endpoints
        ),
        allowlisted_endpoints=(
            snapshot.allowlisted_endpoints
        ),
    )


def _change_id(
    *,
    version: int,
    changed_at: datetime,
    changed_by: str,
    reason: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-target-protection:"
            f"{version}:"
            f"{changed_at.isoformat()}:"
            f"{changed_by}:"
            f"{reason}"
        ),
    )

    return (
        "TPROT-"
        f"{str(value).upper()}"
    )


class TargetProtectionManager:
    def __init__(
        self,
        *,
        store: TargetProtectionSnapshotStore,
        clock=None,
    ):
        self.store = store

        self.clock = (
            clock
            if clock is not None
            else _utc_now
        )

        self._lock = RLock()

    def replace(
        self,
        *,
        changed_by: str,
        reason: str,
        protected_ips=None,
        allowlisted_ips=None,
        protected_accounts=None,
        allowlisted_accounts=None,
        protected_endpoints=None,
        allowlisted_endpoints=None,
    ) -> TargetProtectionSnapshot:
        with self._lock:
            current = (
                self.store.get_snapshot()
            )

            if current is None:
                raise RuntimeError(
                    "Target protection state "
                    "is unavailable."
                )

            next_version = (
                current.version + 1
            )

            snapshot = (
                build_target_protection_snapshot(
                    version=next_version,
                    protected_ips=(
                        current.protected_ips
                        if protected_ips is None
                        else protected_ips
                    ),
                    allowlisted_ips=(
                        current.allowlisted_ips
                        if allowlisted_ips is None
                        else allowlisted_ips
                    ),
                    protected_accounts=(
                        current.protected_accounts
                        if protected_accounts
                        is None
                        else protected_accounts
                    ),
                    allowlisted_accounts=(
                        current.allowlisted_accounts
                        if allowlisted_accounts
                        is None
                        else allowlisted_accounts
                    ),
                    protected_endpoints=(
                        current.protected_endpoints
                        if protected_endpoints
                        is None
                        else protected_endpoints
                    ),
                    allowlisted_endpoints=(
                        current.allowlisted_endpoints
                        if allowlisted_endpoints
                        is None
                        else allowlisted_endpoints
                    ),
                )
            )

            changed_at = self.clock()

            return self.store.apply_update(
                snapshot,
                expected_version=(
                    current.version
                ),
                change_id=_change_id(
                    version=next_version,
                    changed_at=changed_at,
                    changed_by=changed_by,
                    reason=reason,
                ),
                changed_at=changed_at,
                changed_by=changed_by,
                reason=reason,
            )