from app.schemas import SecurityAlertInput
from app.graph.state import InvestigationState


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

    assert state["alert"].alert_id == "ALT-TEST-001"
    assert state["status"] == "received"
    assert state["investigation_iteration"] == 0