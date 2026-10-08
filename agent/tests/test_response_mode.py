import pytest

from app.services.response_mode import (
    evaluate_response_mode,
    normalize_response_mode,
)


def test_default_response_mode_is_supervised():
    assert (
        normalize_response_mode(None)
        == "SUPERVISED"
    )


def test_response_mode_is_case_insensitive():
    assert (
        normalize_response_mode(
            " shadow "
        )
        == "SHADOW"
    )

    assert (
        normalize_response_mode(
            "autonomous"
        )
        == "AUTONOMOUS"
    )


def test_invalid_response_mode_is_rejected():
    with pytest.raises(
        ValueError,
        match="response mode",
    ):
        normalize_response_mode(
            "invalid"
        )


def test_shadow_mode_never_allows_cortex():
    decision = (
        evaluate_response_mode(
            "SHADOW"
        )
    )

    assert (
        decision.mode
        == "SHADOW"
    )

    assert (
        decision.cortex_execution_allowed
        is False
    )


def test_supervised_mode_allows_policy_authorized_cortex():
    decision = (
        evaluate_response_mode(
            "SUPERVISED"
        )
    )

    assert (
        decision.cortex_execution_allowed
        is True
    )


def test_autonomous_mode_allows_policy_authorized_cortex():
    decision = (
        evaluate_response_mode(
            "AUTONOMOUS"
        )
    )

    assert (
        decision.cortex_execution_allowed
        is True
    )