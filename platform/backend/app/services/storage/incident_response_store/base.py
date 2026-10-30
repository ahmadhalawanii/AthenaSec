"""The interface every incident response store follows, plus shared approval rules."""

from typing import Protocol

from app.schemas import (
    ActionExecutionResultRecord,
    ActionRiskAssessmentRecord,
    ActionRollbackRecord,
    ActionVerificationRecord,
    ApprovalRequestRecord,
    IncidentCaseRecord,
    IncidentPolicyDecisionRecord,
    IncidentRiskAssessmentRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)


class IncidentResponseStore(Protocol):
    """Methods every store (in-memory, SQLite, Postgres) must provide."""

    # --- Incident risk assessments -----------------------------------------

    def save_incident_risk(
        self, record: IncidentRiskAssessmentRecord
    ) -> IncidentRiskAssessmentRecord: ...

    def get_incident_risk(
        self, record_id: str
    ) -> IncidentRiskAssessmentRecord | None: ...

    # --- Proposed actions --------------------------------------------------

    def save_proposed_action(
        self, record: ProposedActionRecord
    ) -> ProposedActionRecord: ...

    def get_proposed_action(self, record_id: str) -> ProposedActionRecord | None: ...

    # --- Action risk assessments -------------------------------------------

    def save_action_risk(
        self, record: ActionRiskAssessmentRecord
    ) -> ActionRiskAssessmentRecord: ...

    def get_action_risk(self, record_id: str) -> ActionRiskAssessmentRecord | None: ...

    # --- Policy decisions --------------------------------------------------

    def save_policy_decision(
        self, record: IncidentPolicyDecisionRecord
    ) -> IncidentPolicyDecisionRecord: ...

    def get_policy_decision(
        self, record_id: str
    ) -> IncidentPolicyDecisionRecord | None: ...

    # --- Approval requests -------------------------------------------------

    def save_approval_request(
        self, record: ApprovalRequestRecord
    ) -> ApprovalRequestRecord: ...

    def get_approval_request(self, record_id: str) -> ApprovalRequestRecord | None: ...

    def transition_pending_approval(self, record: ApprovalRequestRecord) -> bool: ...

    def list_approval_requests(
        self, status: str | None = None
    ) -> list[ApprovalRequestRecord]: ...

    # --- Response actions --------------------------------------------------

    def save_response_action(
        self, record: ResponseActionRecord
    ) -> ResponseActionRecord: ...

    def get_response_action(self, record_id: str) -> ResponseActionRecord | None: ...

    # --- Action results ----------------------------------------------------

    def save_action_result(
        self, record: ActionExecutionResultRecord
    ) -> ActionExecutionResultRecord: ...

    def get_action_result(
        self, record_id: str
    ) -> ActionExecutionResultRecord | None: ...

    # --- Action verifications ----------------------------------------------

    def save_action_verification(
        self, record: ActionVerificationRecord
    ) -> ActionVerificationRecord: ...

    def get_action_verification(
        self, record_id: str
    ) -> ActionVerificationRecord | None: ...

    # --- Action rollbacks --------------------------------------------------

    def save_action_rollback(
        self, record: ActionRollbackRecord
    ) -> ActionRollbackRecord: ...

    def get_action_rollback(self, record_id: str) -> ActionRollbackRecord | None: ...

    # --- Response history (Incident Response page), newest first -----------

    def list_response_actions(self) -> list[ResponseActionRecord]: ...

    def list_action_results(self) -> list[ActionExecutionResultRecord]: ...

    def list_action_verifications(self) -> list[ActionVerificationRecord]: ...

    def list_action_rollbacks(self) -> list[ActionRollbackRecord]: ...

    # --- Incident cases ----------------------------------------------------

    def save_incident_case(self, record: IncidentCaseRecord) -> IncidentCaseRecord: ...

    def get_incident_case(self, case_id: str) -> IncidentCaseRecord | None: ...

    def list_incident_cases(self, incident_id: str) -> list[IncidentCaseRecord]: ...

    def list_all_incident_cases(self) -> list[IncidentCaseRecord]: ...


# --- Approval rules shared by all stores --------------------------------------


def _validate_terminal_approval(record):
    if record.status not in {"APPROVED", "REJECTED", "EXPIRED", "CANCELLED"}:
        raise ValueError("Only terminal approval decisions may transition.")
    if record.decided_at is None:
        raise ValueError("Terminal approval requires decided_at.")


def _matches_pending_approval(current, record):
    if current is None or current.status != "PENDING":
        return False
    if (
        current.action_fingerprint != record.action_fingerprint
        or current.policy_decision_id != record.policy_decision_id
        or current.proposed_action_id != record.proposed_action_id
        or current.incident_id != record.incident_id
    ):
        return False
    if record.status == "APPROVED" and (
        current.expires_at is not None and record.decided_at >= current.expires_at
    ):
        return False
    return True
