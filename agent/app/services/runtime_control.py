from datetime import (
    datetime,
    timezone,
)
from threading import RLock
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    RuntimeControlChangeRecord,
    RuntimeControlStateRecord,
)
from app.services.response_mode import (
    normalize_response_mode,
)
from app.services.runtime_control_store import (
    RuntimeControlStore,
)


def _utc_now():
    return datetime.now(
        timezone.utc
    )


def _change_id(
    *,
    version: int,
    changed_at: datetime,
    changed_by: str,
    response_mode: str,
    operator_execution_enabled: bool,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-runtime-control:"
            f"{version}:"
            f"{changed_at.isoformat()}:"
            f"{changed_by}:"
            f"{response_mode}:"
            f"{operator_execution_enabled}"
        ),
    )

    return (
        "RCTRL-"
        f"{str(value).upper()}"
    )


class RuntimeControlManager:
    def __init__(
        self,
        *,
        store: RuntimeControlStore,
        initial_response_mode: str,
        initial_operator_execution_enabled: bool,
        clock=None,
    ):
        self.store = store

        self.clock = (
            clock
            if clock is not None
            else _utc_now
        )

        self._lock = RLock()

        initial_mode = (
            normalize_response_mode(
                initial_response_mode
            )
        )

        existing = (
            self.store.get_state()
        )

        if existing is None:
            initial = (
                RuntimeControlStateRecord(
                    response_mode=initial_mode,
                    operator_execution_enabled=(
                        initial_operator_execution_enabled
                    ),
                    version=0,
                    updated_at=self.clock(),
                    updated_by="system-startup",
                    update_reason=(
                        "Initial AthenaSec "
                        "runtime control state."
                    ),
                )
            )

            existing = (
                self.store.initialize_state(
                    initial
                )
            )

        self._state = existing

    def snapshot(
        self,
    ) -> RuntimeControlStateRecord:
        with self._lock:
            persisted = (
                self.store.get_state()
            )

            if persisted is None:
                raise RuntimeError(
                    "Runtime control state "
                    "is unavailable."
                )

            self._state = persisted

            return persisted

    def update(
        self,
        *,
        changed_by: str,
        reason: str,
        response_mode: str | None = None,
        operator_execution_enabled: (
            bool | None
        ) = None,
    ):
        if (
            response_mode is None
            and operator_execution_enabled
            is None
        ):
            raise ValueError(
                "Runtime control update "
                "must change at least one "
                "control."
            )

        with self._lock:
            current = (
                self.store.get_state()
            )

            if current is None:
                raise RuntimeError(
                    "Runtime control state "
                    "is unavailable."
                )

            self._state = current

            next_mode = (
                normalize_response_mode(
                    response_mode
                )
                if response_mode
                is not None
                else current.response_mode
            )

            if (
                current.response_mode
                == "SHADOW"
                and next_mode
                == "AUTONOMOUS"
            ):
                raise ValueError(
                    "SHADOW mode must transition "
                    "through SUPERVISED before "
                    "AUTONOMOUS mode."
                )

            next_execution_enabled = (
                operator_execution_enabled
                if (
                    operator_execution_enabled
                    is not None
                )
                else (
                    current
                    .operator_execution_enabled
                )
            )

            changed_at = self.clock()

            next_version = (
                current.version + 1
            )

            new_state = (
                RuntimeControlStateRecord(
                    control_id=(
                        current.control_id
                    ),
                    response_mode=next_mode,
                    operator_execution_enabled=(
                        next_execution_enabled
                    ),
                    version=next_version,
                    updated_at=changed_at,
                    updated_by=changed_by,
                    update_reason=reason,
                )
            )

            change = (
                RuntimeControlChangeRecord(
                    change_id=_change_id(
                        version=next_version,
                        changed_at=changed_at,
                        changed_by=changed_by,
                        response_mode=next_mode,
                        operator_execution_enabled=(
                            next_execution_enabled
                        ),
                    ),
                    control_id=(
                        current.control_id
                    ),
                    version=next_version,
                    previous_response_mode=(
                        current.response_mode
                    ),
                    new_response_mode=next_mode,
                    previous_operator_execution_enabled=(
                        current
                        .operator_execution_enabled
                    ),
                    new_operator_execution_enabled=(
                        next_execution_enabled
                    ),
                    changed_at=changed_at,
                    changed_by=changed_by,
                    reason=reason,
                )
            )

            try:
                persisted = (
                    self.store.apply_update(
                        new_state,
                        change,
                        expected_version=(
                            current.version
                        ),
                    )
                )

            except ValueError:
                latest = (
                    self.store.get_state()
                )

                if latest is not None:
                    self._state = latest

                raise

            self._state = persisted

            return (
                persisted,
                change,
            )