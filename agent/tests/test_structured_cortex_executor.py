from datetime import (
    datetime,
    timezone,
)

import pytest

from app.schemas import (
    ProposedActionRecord,
)
from app.services.structured_cortex_executor import (
    CortexStructuredActionExecutor,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    21,
    0,
    tzinfo=timezone.utc,
)


class FakeCortexClient:
    def __init__(self):
        self.calls = []

        self.responder_id = (
            "BlockIp_1_0"
        )

    def run_responder(
        self,
        action: str,
        target: str,
    ):
        self.calls.append(
            (
                action,
                target,
            )
        )

        return {
            "success": True,
            "full": {
                "message": (
                    "IP blocked by Cortex."
                ),
            },
            "operations": [],
        }


def make_block_action(
    *,
    target: str = "203.0.113.10",
    duration_minutes: int = 30,
    parameters=None,
):
    if parameters is None:
        parameters = {
            "duration_minutes": (
                duration_minutes
            ),
        }

    return ProposedActionRecord(
        proposed_action_id=(
            "PACT-CORTEX-001"
        ),
        incident_id="INC-CORTEX-001",
        investigation_id=(
            "INV-CORTEX-001"
        ),
        action_type="block_ip",
        target_type="ip",
        target=target,
        parameters=parameters,
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={},
        reason=(
            "Contain the verified "
            "malicious source."
        ),
        proposed_at=FIXED_TIME,
    )


def test_structured_cortex_uses_exact_proposed_target():
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = make_block_action(
        target="198.51.100.25",
    )

    result = executor.execute(
        action
    )

    assert client.calls == [
        (
            "block_ip",
            "198.51.100.25",
        ),
    ]

    assert (
        result.message
        == "IP blocked by Cortex."
    )

    assert (
        result.details["target"]
        == "198.51.100.25"
    )

    assert (
        result.details[
            "action_type"
        ]
        == "block_ip"
    )

    assert (
        result.details[
            "parameters"
        ]
        == {
            "duration_minutes": 30,
        }
    )

    assert (
        result.details[
            "responder_id"
        ]
        == "BlockIp_1_0"
    )


def test_structured_cortex_does_not_need_alert_metadata():
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = make_block_action(
        target="203.0.113.55",
    )

    executor.execute(
        action
    )

    assert client.calls == [
        (
            "block_ip",
            "203.0.113.55",
        ),
    ]


def test_block_ip_requires_ip_target_type():
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = (
        make_block_action()
        .model_copy(
            update={
                "target_type": (
                    "account"
                ),
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="target_type",
    ):
        executor.execute(
            action
        )

    assert client.calls == []


def test_block_ip_requires_valid_ip_target():
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = make_block_action(
        target="not-an-ip",
    )

    with pytest.raises(
        ValueError,
        match="valid IP",
    ):
        executor.execute(
            action
        )

    assert client.calls == []


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {
            "duration_minutes": 0,
        },
        {
            "duration_minutes": 1441,
        },
        {
            "duration_minutes": True,
        },
        {
            "duration_minutes": 30,
            "unexpected": "value",
        },
    ],
)
def test_block_ip_rejects_invalid_parameters(
    parameters,
):
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = make_block_action(
        parameters=parameters,
    )

    with pytest.raises(
        ValueError,
        match="parameters",
    ):
        executor.execute(
            action
        )

    assert client.calls == []


def test_block_ip_requires_expected_rollback_contract():
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = (
        make_block_action()
        .model_copy(
            update={
                "reversible": False,
                "rollback_action_type": (
                    None
                ),
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="rollback",
    ):
        executor.execute(
            action
        )

    assert client.calls == []


@pytest.mark.parametrize(
    (
        "action_type",
        "target_type",
        "target",
        "parameters",
    ),
    [
        (
            "lock_account",
            "account",
            "root",
            {
                "duration_minutes": 30,
            },
        ),
        (
            "capture_telemetry",
            "endpoint",
            "agent-001",
            {},
        ),
    ],
)
def test_unconfigured_structured_actions_fail_closed(
    action_type,
    target_type,
    target,
    parameters,
):
    client = FakeCortexClient()

    executor = (
        CortexStructuredActionExecutor(
            client=client
        )
    )

    action = ProposedActionRecord(
        proposed_action_id=(
            "PACT-CORTEX-OTHER"
        ),
        incident_id="INC-CORTEX-001",
        investigation_id=(
            "INV-CORTEX-001"
        ),
        action_type=action_type,
        target_type=target_type,
        target=target,
        parameters=parameters,
        reversible=False,
        rollback_action_type=None,
        rollback_parameters={},
        reason=(
            "Test unsupported "
            "structured action."
        ),
        proposed_at=FIXED_TIME,
    )

    with pytest.raises(
        ValueError,
        match="not configured",
    ):
        executor.execute(
            action
        )

    assert client.calls == []