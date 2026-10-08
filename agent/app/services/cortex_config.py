import os
from dataclasses import dataclass

from app.services.cortex_client import (
    HttpCortexClient,
)
from app.services.cortex_executor import (
    CortexResponseExecutor,
)
from app.services.structured_cortex_executor import (
    CortexStructuredActionExecutor,
    CortexStructuredRollbackExecutor,
)


@dataclass(
    frozen=True,
)
class StructuredCortexRuntime:
    executor: CortexStructuredActionExecutor

    rollback_executor: (
        CortexStructuredRollbackExecutor
    )


def build_cortex_response_executor_from_env():
    cortex_url = os.getenv(
        "CORTEX_URL"
    )

    cortex_api_key = os.getenv(
        "CORTEX_API_KEY"
    )

    responder_id = os.getenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID"
    )

    values = [
        cortex_url,
        cortex_api_key,
        responder_id,
    ]

    configured_count = sum(
        value is not None
        and value.strip() != ""
        for value in values
    )

    if configured_count == 0:
        return None

    if configured_count != len(
        values
    ):
        raise RuntimeError(
            "Cortex configuration is incomplete. "
            "CORTEX_URL, CORTEX_API_KEY, and "
            "CORTEX_BLOCK_IP_RESPONDER_ID "
            "must all be configured together."
        )

    client = HttpCortexClient(
        base_url=cortex_url,
        api_key=cortex_api_key,
        responder_id=responder_id,
    )

    return CortexResponseExecutor(
        client=client
    )


def build_structured_cortex_runtime_from_env():
    cortex_url = os.getenv(
        "CORTEX_URL"
    )

    cortex_api_key = os.getenv(
        "CORTEX_API_KEY"
    )

    block_responder_id = os.getenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID"
    )

    unblock_responder_id = os.getenv(
        "CORTEX_UNBLOCK_IP_RESPONDER_ID"
    )

    if (
        unblock_responder_id is None
        or not unblock_responder_id.strip()
    ):
        return None

    values = [
        cortex_url,
        cortex_api_key,
        block_responder_id,
        unblock_responder_id,
    ]

    configured_count = sum(
        value is not None
        and value.strip() != ""
        for value in values
    )

    if configured_count != len(values):
        raise RuntimeError(
            "Structured Cortex configuration "
            "is incomplete. CORTEX_URL, "
            "CORTEX_API_KEY, "
            "CORTEX_BLOCK_IP_RESPONDER_ID, "
            "and "
            "CORTEX_UNBLOCK_IP_RESPONDER_ID "
            "must be configured together."
        )

    block_client = HttpCortexClient(
        base_url=cortex_url,
        api_key=cortex_api_key,
        responder_id=(
            block_responder_id
        ),
    )

    unblock_client = HttpCortexClient(
        base_url=cortex_url,
        api_key=cortex_api_key,
        responder_id=(
            unblock_responder_id
        ),
    )

    return StructuredCortexRuntime(
        executor=(
            CortexStructuredActionExecutor(
                client=block_client
            )
        ),
        rollback_executor=(
            CortexStructuredRollbackExecutor(
                client=unblock_client
            )
        ),
    )