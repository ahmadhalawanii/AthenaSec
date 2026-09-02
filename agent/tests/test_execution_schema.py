from app.schemas import (
    ActionExecutionResult,
    ResponseExecutionResult,
)


def test_response_execution_result_accepts_successful_action():
    result = ResponseExecutionResult(
        policy_id="POL-BF-CRITICAL",
        executor="cortex",
        status="completed",
        action_results=[
            ActionExecutionResult(
                action="block_ip",
                status="completed",
                message=(
                    "Source IP was blocked."
                ),
            ),
        ],
    )

    assert (
        result.policy_id
        == "POL-BF-CRITICAL"
    )

    assert result.executor == "cortex"

    assert result.status == "completed"

    assert len(
        result.action_results
    ) == 1

    assert (
        result.action_results[0].action
        == "block_ip"
    )


def test_response_execution_result_can_record_failure():
    result = ResponseExecutionResult(
        policy_id="POL-BF-CRITICAL",
        executor="cortex",
        status="failed",
        action_results=[
            ActionExecutionResult(
                action="block_ip",
                status="failed",
                message=(
                    "Cortex responder failed."
                ),
            ),
        ],
    )

    assert result.status == "failed"

    assert (
        result.action_results[0].status
        == "failed"
    )

def test_action_execution_result_can_store_details():
    result = ActionExecutionResult(
        action="block_ip",
        status="completed",
        message=(
            "IP successfully blocked "
            "by Cortex responder."
        ),
        details={
            "target": "203.0.113.50",
            "responder_id": "BlockIp_1_0",
            "cortex_result": {
                "success": True,
                "operations": [],
            },
        },
    )

    assert (
        result.details["target"]
        == "203.0.113.50"
    )

    assert (
        result.details["responder_id"]
        == "BlockIp_1_0"
    )

    assert (
        result.details[
            "cortex_result"
        ]["success"]
        is True
    )