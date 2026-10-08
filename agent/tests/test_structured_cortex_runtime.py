import json

import httpx
import pytest

from datetime import (
    datetime,
    timezone,
)

from app.schemas import (
    ProposedActionRecord,
)
from app.services.cortex_client import (
    HttpCortexClient,
)
from app.services.cortex_config import (
    build_structured_cortex_runtime_from_env,
)
from app.services.structured_cortex_executor import (
    CortexStructuredRollbackExecutor,
)


FIXED_TIME = datetime(
    2026,
    10,
    9,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_action():
    return ProposedActionRecord(
        proposed_action_id=(
            "PACT-ROLLBACK-CORTEX"
        ),
        incident_id="INC-001",
        investigation_id="INV-001",
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
        reason="Temporary block.",
        proposed_at=FIXED_TIME,
    )


class FakeClient:
    responder_id = "UnblockIp_1_0"

    def __init__(self):
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

        return {
            "success": True,
            "full": {
                "message": (
                    "IP unblocked."
                ),
            },
            "operations": [],
        }


def test_structured_cortex_rollback_uses_exact_target():
    client = FakeClient()

    executor = (
        CortexStructuredRollbackExecutor(
            client=client
        )
    )

    result = executor.rollback(
        make_action()
    )

    assert client.calls == [
        (
            "unblock_ip",
            "203.0.113.10",
        )
    ]

    assert (
        result.message
        == "IP unblocked."
    )


def test_structured_cortex_rollback_requires_contract():
    client = FakeClient()

    executor = (
        CortexStructuredRollbackExecutor(
            client=client
        )
    )

    action = (
        make_action()
        .model_copy(
            update={
                "rollback_action_type": (
                    "wrong_action"
                ),
            }
        )
    )

    with pytest.raises(
        ValueError,
        match="rollback",
    ):
        executor.rollback(
            action
        )

    assert client.calls == []


def test_http_cortex_client_supports_unblock_ip():
    requests = []

    def transport(
        request,
    ):
        requests.append(
            request
        )

        return httpx.Response(
            status_code=200,
            json={
                "success": True,
                "operations": [],
            },
        )

    client = HttpCortexClient(
        base_url="http://cortex:9001",
        api_key="secret",
        responder_id="UnblockIp_1_0",
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                transport
            )
        ),
    )

    client.run_responder(
        action="unblock_ip",
        target="203.0.113.10",
    )

    assert len(requests) == 1

    body = json.loads(
        requests[0]
        .content
        .decode("utf-8")
    )

    assert (
        body["data"]
        == "203.0.113.10"
    )

    assert (
        body["dataType"]
        == "ip"
    )


def test_structured_cortex_runtime_builds_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "CORTEX_URL",
        "http://cortex:9001",
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret",
    )

    monkeypatch.setenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        "BlockIp_1_0",
    )

    monkeypatch.setenv(
        "CORTEX_UNBLOCK_IP_RESPONDER_ID",
        "UnblockIp_1_0",
    )

    runtime = (
        build_structured_cortex_runtime_from_env()
    )

    assert runtime is not None

    assert (
        runtime.executor
        .client
        .responder_id
        == "BlockIp_1_0"
    )

    assert (
        runtime.rollback_executor
        .client
        .responder_id
        == "UnblockIp_1_0"
    )


def test_structured_runtime_is_none_without_unblock_responder(
    monkeypatch,
):
    monkeypatch.setenv(
        "CORTEX_URL",
        "http://cortex:9001",
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret",
    )

    monkeypatch.setenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        "BlockIp_1_0",
    )

    monkeypatch.delenv(
        "CORTEX_UNBLOCK_IP_RESPONDER_ID",
        raising=False,
    )

    assert (
        build_structured_cortex_runtime_from_env()
        is None
    )


def test_partial_structured_runtime_configuration_is_rejected(
    monkeypatch,
):
    monkeypatch.delenv(
        "CORTEX_URL",
        raising=False,
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret",
    )

    monkeypatch.setenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        "BlockIp_1_0",
    )

    monkeypatch.setenv(
        "CORTEX_UNBLOCK_IP_RESPONDER_ID",
        "UnblockIp_1_0",
    )

    with pytest.raises(
        RuntimeError,
        match="Structured Cortex",
    ):
        build_structured_cortex_runtime_from_env()