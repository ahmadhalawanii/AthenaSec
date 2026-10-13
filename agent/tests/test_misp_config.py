import pytest

from app.services.misp_config import (
    UnavailableMISPClient,
    build_live_misp_client,
    build_misp_client_from_env,
)
from app.services.misp_http_client import (
    HttpMISPClient,
)


def test_build_misp_client_from_env_returns_http_client(
    monkeypatch,
):
    monkeypatch.setenv(
        "MISP_URL",
        "https://misp.local",
    )

    monkeypatch.setenv(
        "MISP_API_KEY",
        "test-misp-key",
    )

    client = build_misp_client_from_env()

    assert isinstance(
        client,
        HttpMISPClient,
    )

    assert (
        client.base_url
        == "https://misp.local"
    )

    assert (
        client.api_key
        == "test-misp-key"
    )


def test_build_misp_client_from_env_rejects_missing_configuration(
    monkeypatch,
):
    monkeypatch.delenv(
        "MISP_URL",
        raising=False,
    )

    monkeypatch.delenv(
        "MISP_API_KEY",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="MISP_URL",
    ):
        build_misp_client_from_env()


def test_build_live_misp_client_returns_unavailable_client_on_failure(
    monkeypatch,
):
    monkeypatch.delenv(
        "MISP_URL",
        raising=False,
    )

    monkeypatch.delenv(
        "MISP_API_KEY",
        raising=False,
    )

    client = build_live_misp_client()

    assert isinstance(
        client,
        UnavailableMISPClient,
    )

    with pytest.raises(
        RuntimeError,
        match="MISP_URL",
    ):
        client.enrich(
            []
        )