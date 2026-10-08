import ipaddress
import re
from datetime import datetime
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    ProposedActionRecord,
    ResponseActionProposal,
    StructuredResponseProposal,
)


ACCOUNT_PATTERN = re.compile(
    r"\b(?:"
    r"target_user|"
    r"source_user|"
    r"dstuser|"
    r"srcuser|"
    r"user"
    r")\s*=\s*"
    r"([A-Za-z0-9_.@\\-]+)",
    re.IGNORECASE,
)


ENDPOINT_PATTERN = re.compile(
    r"\b(?:"
    r"agent_id|"
    r"agent_name|"
    r"hostname|"
    r"host|"
    r"endpoint|"
    r"device|"
    r"machine"
    r")\s*=\s*"
    r"([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


EXPECTED_TARGET_TYPE = {
    "block_ip": "ip",
    "lock_account": "account",
    "capture_telemetry": "endpoint",
}


def _normalized(
    value,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip()

    if not value:
        return None

    return value.lower()


def _grounded_ips(
    state: InvestigationState,
) -> set[str]:
    values: set[str] = set()

    alert = state["alert"]

    metadata_ip = (
        alert.metadata.get(
            "source_ip"
        )
    )

    if isinstance(
        metadata_ip,
        str,
    ):
        try:
            values.add(
                str(
                    ipaddress.ip_address(
                        metadata_ip.strip()
                    )
                )
            )
        except ValueError:
            pass

    for record in state.get(
        "evidence_records",
        [],
    ):
        words = re.findall(
            r"(?<![\d.])"
            r"(?:\d{1,3}\.){3}\d{1,3}"
            r"(?!\d|\.\d)",
            record.content,
        )

        for word in words:
            try:
                values.add(
                    str(
                        ipaddress.ip_address(
                            word
                        )
                    )
                )
            except ValueError:
                continue

    return values


def _grounded_accounts(
    state: InvestigationState,
) -> set[str]:
    values: set[str] = set()

    alert = state["alert"]

    for key in (
        "target_user",
        "source_user",
    ):
        value = _normalized(
            alert.metadata.get(
                key
            )
        )

        if value:
            values.add(
                value
            )

    for record in state.get(
        "evidence_records",
        [],
    ):
        values.update(
            match.lower()
            for match
            in ACCOUNT_PATTERN.findall(
                record.content
            )
        )

    return values


def _grounded_endpoints(
    state: InvestigationState,
) -> set[str]:
    values: set[str] = set()

    alert = state["alert"]

    for key in (
        "agent_id",
        "agent_name",
    ):
        value = _normalized(
            alert.metadata.get(
                key
            )
        )

        if value:
            values.add(
                value
            )

    for record in state.get(
        "evidence_records",
        [],
    ):
        values.update(
            match.lower()
            for match
            in ENDPOINT_PATTERN.findall(
                record.content
            )
        )

    return values


def _validate_evidence_refs(
    action: ResponseActionProposal,
    state: InvestigationState,
) -> None:
    available = {
        record.evidence_id
        for record in state.get(
            "evidence_records",
            [],
        )
    }

    missing = [
        evidence_id
        for evidence_id
        in action.evidence_refs
        if evidence_id
        not in available
    ]

    if missing:
        raise ValueError(
            "Response proposal references "
            "unavailable evidence: "
            + ", ".join(
                missing
            )
        )


def _validate_action(
    action: ResponseActionProposal,
    state: InvestigationState,
) -> None:
    expected_target_type = (
        EXPECTED_TARGET_TYPE[
            action.action_type
        ]
    )

    if (
        action.target_type
        != expected_target_type
    ):
        raise ValueError(
            "Response proposal target type "
            f"for {action.action_type} "
            f"must be {expected_target_type}."
        )

    _validate_evidence_refs(
        action,
        state,
    )

    if action.action_type == "block_ip":
        if action.duration_minutes is None:
            raise ValueError(
                "block_ip requires a temporary "
                "duration."
            )

        try:
            target = str(
                ipaddress.ip_address(
                    action.target
                )
            )

        except ValueError as exc:
            raise ValueError(
                "block_ip target must be "
                "a valid IP address."
            ) from exc

        if target not in _grounded_ips(
            state
        ):
            raise ValueError(
                "block_ip target is not grounded "
                "in the supplied alert or evidence."
            )

        return

    if action.action_type == "lock_account":
        if action.duration_minutes is None:
            raise ValueError(
                "lock_account requires a "
                "temporary duration."
            )

        target = _normalized(
            action.target
        )

        if (
            target is None
            or target
            not in _grounded_accounts(
                state
            )
        ):
            raise ValueError(
                "lock_account target is not grounded "
                "in the supplied alert or evidence."
            )

        return

    if action.action_type == "capture_telemetry":
        if (
            action.duration_minutes
            is not None
        ):
            raise ValueError(
                "capture_telemetry does not "
                "accept a duration."
            )

        target = _normalized(
            action.target
        )

        if (
            target is None
            or target
            not in _grounded_endpoints(
                state
            )
        ):
            raise ValueError(
                "capture_telemetry target is "
                "not grounded in the supplied "
                "alert or evidence."
            )

        return

    raise ValueError(
        "Unsupported response proposal action."
    )


def validate_response_proposal(
    *,
    proposal: StructuredResponseProposal,
    state: InvestigationState,
) -> None:
    verification = state.get(
        "analysis_verification"
    )

    if (
        verification is None
        or not verification.verified
    ):
        raise ValueError(
            "Response proposal requires a "
            "verified investigation analysis."
        )

    for action in proposal.actions:
        _validate_action(
            action,
            state,
        )


def _action_parameters(
    action: ResponseActionProposal,
) -> dict[str, object]:
    if (
        action.duration_minutes
        is None
    ):
        return {}

    return {
        "duration_minutes": (
            action.duration_minutes
        ),
    }


def _rollback_fields(
    action: ResponseActionProposal,
) -> tuple[
    bool,
    str | None,
    dict[str, object],
]:
    if action.action_type == "block_ip":
        return (
            True,
            "unblock_ip",
            {},
        )

    if action.action_type == "lock_account":
        return (
            True,
            "unlock_account",
            {},
        )

    return (
        False,
        None,
        {},
    )


def _proposed_action_id(
    *,
    incident_id: str,
    investigation_id: str,
    sequence: int,
    action: ResponseActionProposal,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-proposed-action:"
            f"{incident_id}:"
            f"{investigation_id}:"
            f"{sequence}:"
            f"{action.action_type}:"
            f"{action.target}:"
            f"{action.duration_minutes}"
        ),
    )

    return (
        "PACT-"
        f"{str(value).upper()}"
    )


def build_proposed_action_records(
    *,
    proposal: StructuredResponseProposal,
    incident_id: str,
    investigation_id: str,
    proposed_at: datetime,
) -> list[ProposedActionRecord]:
    records: list[
        ProposedActionRecord
    ] = []

    for sequence, action in enumerate(
        proposal.actions,
        start=1,
    ):
        (
            reversible,
            rollback_action_type,
            rollback_parameters,
        ) = _rollback_fields(
            action
        )

        records.append(
            ProposedActionRecord(
                proposed_action_id=(
                    _proposed_action_id(
                        incident_id=incident_id,
                        investigation_id=(
                            investigation_id
                        ),
                        sequence=sequence,
                        action=action,
                    )
                ),
                incident_id=incident_id,
                investigation_id=(
                    investigation_id
                ),
                action_type=(
                    action.action_type
                ),
                target_type=(
                    action.target_type
                ),
                target=action.target,
                parameters=(
                    _action_parameters(
                        action
                    )
                ),
                reversible=reversible,
                rollback_action_type=(
                    rollback_action_type
                ),
                rollback_parameters=(
                    rollback_parameters
                ),
                reason=action.reason,
                proposed_at=proposed_at,
            )
        )

    return records