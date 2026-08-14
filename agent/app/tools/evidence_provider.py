import os

from app.tools.mock_wazuh import (
    gather_requested_evidence,
)
from app.tools.wazuh_indexer import (
    WazuhEvidenceProvider,
    WazuhIndexerClient,
)


def _as_bool(
    value: str,
) -> bool:
    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def create_evidence_provider():
    mode = os.getenv(
        "ATHENASEC_EVIDENCE_PROVIDER",
        "mock",
    ).strip().lower()

    if mode == "mock":
        return gather_requested_evidence

    if mode != "wazuh":
        raise ValueError(
            "ATHENASEC_EVIDENCE_PROVIDER "
            "must be 'mock' or 'wazuh'."
        )

    base_url = os.getenv(
        "WAZUH_INDEXER_URL",
    )

    username = os.getenv(
        "WAZUH_INDEXER_USERNAME",
    )

    password = os.getenv(
        "WAZUH_INDEXER_PASSWORD",
    )

    missing = [
        name
        for name, value in {
            "WAZUH_INDEXER_URL": (
                base_url
            ),
            "WAZUH_INDEXER_USERNAME": (
                username
            ),
            "WAZUH_INDEXER_PASSWORD": (
                password
            ),
        }.items()
        if not value
    ]

    if missing:
        raise RuntimeError(
            "Missing Wazuh configuration: "
            + ", ".join(missing)
        )

    verify_ssl = _as_bool(
        os.getenv(
            "WAZUH_VERIFY_SSL",
            "true",
        )
    )

    client = WazuhIndexerClient(
        base_url=base_url,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
    )

    provider = WazuhEvidenceProvider(
        client
    )

    return provider.gather