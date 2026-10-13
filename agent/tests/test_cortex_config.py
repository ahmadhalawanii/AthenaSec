from app.services.cortex_config import (
    build_cortex_response_executor_from_env,
)


def test_builds_cortex_executor_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "CORTEX_URL",
        "http://cortex:9001",
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret-api-key",
    )

    monkeypatch.setenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        "BlockIp_1_0",
    )

    executor = (
        build_cortex_response_executor_from_env()
    )

    assert executor is not None

    assert (
        executor.client.base_url
        == "http://cortex:9001"
    )

    assert (
        executor.client.api_key
        == "secret-api-key"
    )

    assert (
        executor.client.responder_id
        == "BlockIp_1_0"
    )


def test_returns_none_when_cortex_is_not_configured(
    monkeypatch,
):
    monkeypatch.delenv(
        "CORTEX_URL",
        raising=False,
    )

    monkeypatch.delenv(
        "CORTEX_API_KEY",
        raising=False,
    )

    monkeypatch.delenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        raising=False,
    )

    executor = (
        build_cortex_response_executor_from_env()
    )

    assert executor is None


def test_partial_cortex_configuration_is_rejected(
    monkeypatch,
):
    monkeypatch.setenv(
        "CORTEX_URL",
        "http://cortex:9001",
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret-api-key",
    )

    monkeypatch.delenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        raising=False,
    )

    try:
        build_cortex_response_executor_from_env()

        assert False, (
            "Expected partial Cortex "
            "configuration to be rejected."
        )

    except RuntimeError as exc:
        assert (
            "Cortex configuration"
            in str(exc)
        )