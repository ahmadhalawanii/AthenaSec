from datetime import (
    datetime,
    timezone,
)

import pytest

from app.schemas import (
    ActionExecutionResultRecord,
    ProposedActionRecord,
)
from app.services.structured_cortex_verifier import (
    CortexBlockIpStateVerifier,
)


FIXED_TIME = datetime(
    2026,
    10,
    9,
    13,
    0,
    tzinfo=timezone.utc,
)


def make_action():
    return ProposedActionRecord(
        proposed_action_id=(
            "PACT-VERIFY-CORTEX-001"
        ),
        incident_id=(
            "INC-VERIFY-CORTEX-001"
        ),
        investigation_id=(
            "INV-VERIFY-CORTEX-001"
        ),
        action_type="block_ip",
        target_type="ip",
        target="203.0.113.10",
        parameters={
            "duration_minutes": 30,
        },
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={},
        reason="Temporary containment.",
        proposed_at=FIXED_TIME,
    )


def make_result():
    return ActionExecutionResultRecord(
        action_result_id=(
            "ARES-VERIFY-CORTEX-001"
        ),
        response_action_id=(
            "ACT-VERIFY-CORTEX-001"
        ),
        status="completed",
        message="Cortex block completed.",
        details={},
        recorded_at=FIXED_TIME,
    )


class FakeVerificationClient:
    responder_id = (
        "VerifyBlockIp_1_0"
    )

    def __init__(
        self,
        payload,
    ):
        self.payload = payload
        self.calls = []

    def run_responder(
        self,
        action,
        target,
    ):
        self.calls.append(
            (
                action,
                target,
            )
        )

        return self.payload


def test_block_state_true_is_success():
    client = FakeVerificationClient(
        {
            "success": True,
            "full": {
                "target": (
                    "203.0.113.10"
                ),
                "blocked": True,
            },
        }
    )

    verifier = (
        CortexBlockIpStateVerifier(
            client=client
        )
    )

    observation = verifier.verify(
        make_action(),
        make_result(),
    )

    assert (
        observation.status
        == "SUCCESS"
    )

    assert client.calls == [
        (
            "verify_block_ip",
            "203.0.113.10",
        )
    ]

    assert (
        observation.details[
            "blocked"
        ]
        is True
    )


def test_block_state_false_is_failed():
    client = FakeVerificationClient(
        {
            "success": True,
            "full": {
                "target": (
                    "203.0.113.10"
                ),
                "blocked": False,
            },
        }
    )

    verifier = (
        CortexBlockIpStateVerifier(
            client=client
        )
    )

    observation = verifier.verify(
        make_action(),
        make_result(),
    )

    assert (
        observation.status
        == "FAILED"
    )


def test_verification_requires_exact_target():
    client = FakeVerificationClient(
        {
            "success": True,
            "full": {
                "target": (
                    "198.51.100.25"
                ),
                "blocked": True,
            },
        }
    )

    verifier = (
        CortexBlockIpStateVerifier(
            client=client
        )
    )

    with pytest.raises(
        RuntimeError,
        match="target",
    ):
        verifier.verify(
            make_action(),
            make_result(),
        )


def test_verification_requires_boolean_block_state():
    client = FakeVerificationClient(
        {
            "success": True,
            "full": {
                "target": (
                    "203.0.113.10"
                ),
            },
        }
    )

    verifier = (
        CortexBlockIpStateVerifier(
            client=client
        )
    )

    with pytest.raises(
        RuntimeError,
        match="blocked",
    ):
        verifier.verify(
            make_action(),
            make_result(),
        )


def test_verifier_rejects_unsupported_action():
    client = FakeVerificationClient(
        {
            "success": True,
            "full": {
                "target": (
                    "203.0.113.10"
                ),
                "blocked": True,
            },
        }
    )

    verifier = (
        CortexBlockIpStateVerifier(
            client=client
        )
    )

    action = (
        make_action()
        .model_copy(
            update={
                "action_type": (
                    "capture_telemetry"
                ),
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="block_ip",
    ):
        verifier.verify(
            action,
            make_result(),
        )

    assert client.calls == []