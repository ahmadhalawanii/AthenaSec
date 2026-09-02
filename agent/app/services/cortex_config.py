import os

from app.services.cortex_client import (
    HttpCortexClient,
)
from app.services.cortex_executor import (
    CortexResponseExecutor,
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