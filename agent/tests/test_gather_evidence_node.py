from app.graph.nodes.gather_evidence import (
    make_gather_evidence_node,
)
from app.schemas import SecurityAlertInput


def fake_evidence_provider(
    alert: SecurityAlertInput,
) -> list[str]:
    return [
        "No successful SSH authentication was found",
        "Source belongs to workstation-07",
    ]


def test_gather_evidence_updates_state():
    node = make_gather_evidence_node(
        fake_evidence_provider
    )

    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH failures detected.",
    )

    result = node(
        {
            "alert": alert,
            "gathered_evidence": [],
            "investigation_iteration": 0,
            "status": "needs_evidence",
        }
    )

    assert result["gathered_evidence"] == [
        "No successful SSH authentication was found",
        "Source belongs to workstation-07",
    ]

    assert result["investigation_iteration"] == 1

    assert result["status"] == "evidence_gathered"