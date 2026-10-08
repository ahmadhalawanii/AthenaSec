from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from app.schemas import (
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.action_approval import (
    approval_matches_action,
    build_action_fingerprint,
    create_approval_request,
    decide_approval_request,
)


REQUESTED_AT = datetime(
    2026,
    10,
    8,
    16,
    0,
    tzinfo=timezone.utc,
)


EXPIRES_AT = (
    REQUESTED_AT
    + timedelta(minutes=30)
)


def make_action(
    *,
    proposed_action_id: str = "PACT-001",
    target: str = "203.0.113.10",
    duration_minutes: int = 480,
) -> ProposedActionRecord:
    return ProposedActionRecord(
        proposed_action_id=(
            proposed_action_id
        ),
        incident_id="INC-001",
        investigation_id="INV-001",
        action_type="block_ip",
        target_type="ip",
        target=target,
        parameters={
            "duration_minutes": (
                duration_minutes
            ),
        },
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={},
        reason=(
            "Contain the confirmed "
            "malicious source."
        ),
        proposed_at=REQUESTED_AT,
    )


def make_policy_decision(
    *,
    outcome: str = (
        "APPROVAL_REQUIRED"
    ),
    proposed_action_id: str = (
        "PACT-001"
    ),
) -> IncidentPolicyDecisionRecord:
    return IncidentPolicyDecisionRecord(
        decision_id="PDEC-001",
        incident_id="INC-001",
        proposed_action_id=(
            proposed_action_id
        ),
        policy_id=(
            "POL-ACTION-HUMAN-APPROVAL"
        ),
        outcome=outcome,
        reason=(
            "Human approval is required."
        ),
        decided_at=REQUESTED_AT,
    )


def test_action_fingerprint_is_deterministic():
    action = make_action()

    first = build_action_fingerprint(
        action
    )

    second = build_action_fingerprint(
        action
    )

    assert first == second

    assert first.startswith(
        "sha256:"
    )


def test_fingerprint_changes_when_target_changes():
    original = (
        build_action_fingerprint(
            make_action()
        )
    )

    changed = (
        build_action_fingerprint(
            make_action(
                target="198.51.100.20",
            )
        )
    )

    assert original != changed


def test_fingerprint_changes_when_duration_changes():
    original = (
        build_action_fingerprint(
            make_action(
                duration_minutes=480,
            )
        )
    )

    changed = (
        build_action_fingerprint(
            make_action(
                duration_minutes=600,
            )
        )
    )

    assert original != changed


def test_approval_request_binds_exact_action():
    action = make_action()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    assert (
        approval.status
        == "PENDING"
    )

    assert (
        approval.incident_id
        == "INC-001"
    )

    assert (
        approval.proposed_action_id
        == "PACT-001"
    )

    assert (
        approval.policy_decision_id
        == "PDEC-001"
    )

    assert (
        approval.action_fingerprint
        == build_action_fingerprint(
            action
        )
    )

    assert (
        approval.requested_by
        == "athenasec-policy"
    )

    assert (
        approval_matches_action(
            approval,
            action,
        )
        is True
    )


def test_non_approval_policy_cannot_create_approval():
    with pytest.raises(
        ValueError,
        match="APPROVAL_REQUIRED",
    ):
        create_approval_request(
            proposed_action=(
                make_action()
            ),
            policy_decision=(
                make_policy_decision(
                    outcome=(
                        "AUTO_ALLOWED"
                    )
                )
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )


def test_policy_and_action_identity_must_match():
    with pytest.raises(
        ValueError,
        match="proposed action",
    ):
        create_approval_request(
            proposed_action=(
                make_action()
            ),
            policy_decision=(
                make_policy_decision(
                    proposed_action_id=(
                        "PACT-OTHER"
                    )
                )
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )


def test_exact_action_can_be_approved():
    action = make_action()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    decided = (
        decide_approval_request(
            approval=approval,
            proposed_action=action,
            decision="APPROVED",
            decided_by="analyst-001",
            reason=(
                "Approved temporary "
                "containment."
            ),
            decided_at=(
                REQUESTED_AT
                + timedelta(minutes=5)
            ),
        )
    )

    assert (
        decided.status
        == "APPROVED"
    )

    assert (
        decided.decided_by
        == "analyst-001"
    )

    assert (
        decided.decision_reason
        == (
            "Approved temporary "
            "containment."
        )
    )


def test_modified_action_cannot_use_existing_approval():
    original = make_action()

    approval = (
        create_approval_request(
            proposed_action=original,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    modified = make_action(
        duration_minutes=600,
    )

    assert (
        approval_matches_action(
            approval,
            modified,
        )
        is False
    )

    with pytest.raises(
        ValueError,
        match="fingerprint",
    ):
        decide_approval_request(
            approval=approval,
            proposed_action=modified,
            decision="APPROVED",
            decided_by="analyst-001",
            reason="Approve.",
            decided_at=(
                REQUESTED_AT
                + timedelta(minutes=5)
            ),
        )


def test_action_can_be_rejected():
    action = make_action()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    decided = (
        decide_approval_request(
            approval=approval,
            proposed_action=action,
            decision="REJECTED",
            decided_by="analyst-002",
            reason=(
                "Containment impact "
                "is too high."
            ),
            decided_at=(
                REQUESTED_AT
                + timedelta(minutes=3)
            ),
        )
    )

    assert (
        decided.status
        == "REJECTED"
    )


def test_expired_approval_cannot_authorize_action():
    action = make_action()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    decided = (
        decide_approval_request(
            approval=approval,
            proposed_action=action,
            decision="APPROVED",
            decided_by="analyst-001",
            reason="Approved too late.",
            decided_at=(
                EXPIRES_AT
                + timedelta(seconds=1)
            ),
        )
    )

    assert (
        decided.status
        == "EXPIRED"
    )

    assert (
        decided.decided_at
        == (
            EXPIRES_AT
            + timedelta(seconds=1)
        )
    )


def test_decided_approval_cannot_be_decided_again():
    action = make_action()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=(
                make_policy_decision()
            ),
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    approved = (
        decide_approval_request(
            approval=approval,
            proposed_action=action,
            decision="APPROVED",
            decided_by="analyst-001",
            reason="Approved.",
            decided_at=(
                REQUESTED_AT
                + timedelta(minutes=1)
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="PENDING",
    ):
        decide_approval_request(
            approval=approved,
            proposed_action=action,
            decision="REJECTED",
            decided_by="analyst-002",
            reason="Changed mind.",
            decided_at=(
                REQUESTED_AT
                + timedelta(minutes=2)
            ),
        )


def test_approval_id_is_deterministic():
    action = make_action()

    policy = make_policy_decision()

    first = create_approval_request(
        proposed_action=action,
        policy_decision=policy,
        requested_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    )

    second = create_approval_request(
        proposed_action=action,
        policy_decision=policy,
        requested_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    )

    assert (
        first.approval_id
        == second.approval_id
    )

def test_approval_expires_at_exact_boundary():
    action = make_action()

    approval = create_approval_request(
        proposed_action=action,
        policy_decision=(
            make_policy_decision()
        ),
        requested_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    )

    decided = decide_approval_request(
        approval=approval,
        proposed_action=action,
        decision="APPROVED",
        decided_by="analyst-001",
        reason="Boundary decision.",
        decided_at=EXPIRES_AT,
    )

    assert decided.status == "EXPIRED"
