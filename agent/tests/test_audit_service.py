from app.services.audit_service import (
    create_audit_record,
)


def test_create_audit_record_builds_expected_record():
    record = create_audit_record(
        alert_id="ALT-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={
            "source": "wazuh",
        },
    )

    assert record.alert_id == "ALT-001"

    assert (
        record.event_type
        == "investigation_created"
    )

    assert (
        record.message
        == "Investigation was created."
    )

    assert (
        record.details["source"]
        == "wazuh"
    )

    assert record.audit_id.startswith(
        "AUD-"
    )


def test_audit_ids_are_unique_for_distinct_events():
    first = create_audit_record(
        alert_id="ALT-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={},
    )

    second = create_audit_record(
        alert_id="ALT-001",
        event_type="policy_evaluated",
        message="Policy was evaluated.",
        details={},
    )

    assert (
        first.audit_id
        != second.audit_id
    )