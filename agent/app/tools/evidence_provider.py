import os
from pathlib import Path
from urllib.parse import urlsplit

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

    parsed_url = urlsplit(base_url)
    if (
        parsed_url.scheme != "https" or not parsed_url.hostname
        or parsed_url.username or parsed_url.password
        or parsed_url.query or parsed_url.fragment
    ):
        raise ValueError("Wazuh Indexer requires a clean HTTPS URL")

    if username.strip().casefold() in {"admin", "root"}:
        raise ValueError("Wazuh Indexer requires a non-administrator service user")

    verify_setting = os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower()
    if verify_setting not in {"1", "true", "yes", "on"}:
        raise ValueError("TLS certificate verification must remain enabled")

    ca_bundle = os.getenv("WAZUH_INDEXER_CA_BUNDLE", "").strip()
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ValueError("Wazuh Indexer CA bundle file does not exist")
    legacy_flag = os.getenv("WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT", "false")
    legacy_flag = legacy_flag.strip().lower()
    if legacy_flag not in {"0", "false", "no", "off", "1", "true", "yes", "on"}:
        raise ValueError("Invalid legacy CA compatibility flag")
    legacy_compat = legacy_flag in {"1", "true", "yes", "on"}
    if legacy_compat and not ca_bundle:
        raise ValueError("Legacy CA compatibility requires an explicit CA bundle")

    # Strict verification is the default. The legacy mode is an explicit
    # existing-lab compatibility exception, NOT production certificate repair.
    client = WazuhIndexerClient(
        base_url=base_url,
        username=username,
        password=password,
        verify_ssl=ca_bundle if ca_bundle else True,
        legacy_ca_compat=legacy_compat,
    )

    provider = WazuhEvidenceProvider(client)
    return provider.gather
