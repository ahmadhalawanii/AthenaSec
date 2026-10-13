from app.graph.state import InvestigationState
from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)


def test_investigation_state_accepts_security_alert():
    alert = SecurityAlertInput(
        alert_id="ALT-TEST-001",
        source="mock",
        event_text="148 failed SSH login attempts.",
    )

    state: InvestigationState = {
        "alert": alert,
        "status": "received",
        "investigation_iteration": 0,
        "gathered_evidence": [],
    }

    assert (
        state["alert"].alert_id
        == "ALT-TEST-001"
    )

    assert (
        state["status"]
        == "received"
    )

    assert (
        state["investigation_iteration"]
        == 0
    )


def test_investigation_state_declares_ml_prediction():
    assert (
        "ml_prediction"
        in InvestigationState.__annotations__
    )

    assert (
        InvestigationState.__annotations__[
            "ml_prediction"
        ]
        is AttackPrediction
    )