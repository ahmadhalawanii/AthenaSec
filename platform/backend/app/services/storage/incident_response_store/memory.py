"""In-memory store. Keeps everything in Python dicts; used in tests and local demos."""

from threading import RLock

from app.services.storage.incident_response_store.base import (
    _matches_pending_approval,
    _validate_terminal_approval,
)


class InMemoryIncidentResponseStore:
    """Stores records in memory. Data is lost when the process stops."""

    # --- Setup -------------------------------------------------------------

    def __init__(self):
        self._incident_risks = {}
        self._proposed_actions = {}
        self._action_risks = {}
        self._policy_decisions = {}
        self._approval_requests = {}
        self._approval_lock = RLock()
        self._response_actions = {}
        self._action_results = {}
        self._action_verifications = {}
        self._action_rollbacks = {}
        self._incident_cases = {}

    # --- Incident risk assessments -----------------------------------------

    def save_incident_risk(self, record):
        self._incident_risks[record.risk_assessment_id] = record
        return record

    def get_incident_risk(self, record_id):
        return self._incident_risks.get(record_id)

    # --- Proposed actions --------------------------------------------------

    def save_proposed_action(self, record):
        self._proposed_actions[record.proposed_action_id] = record
        return record

    def get_proposed_action(self, record_id):
        return self._proposed_actions.get(record_id)

    # --- Action risk assessments -------------------------------------------

    def save_action_risk(self, record):
        self._action_risks[record.action_risk_id] = record
        return record

    def get_action_risk(self, record_id):
        return self._action_risks.get(record_id)

    # --- Policy decisions --------------------------------------------------

    def save_policy_decision(self, record):
        self._policy_decisions[record.decision_id] = record
        return record

    def get_policy_decision(self, record_id):
        return self._policy_decisions.get(record_id)

    # --- Approval requests -------------------------------------------------

    def save_approval_request(self, record):
        with self._approval_lock:
            existing = self._approval_requests.get(record.approval_id)
            if existing is not None:
                # Replayed PENDING requests must never undo a terminal decision.
                if existing.status != "PENDING" or record.status == "PENDING":
                    return existing
                if (
                    existing.action_fingerprint != record.action_fingerprint
                    or existing.policy_decision_id != record.policy_decision_id
                    or existing.proposed_action_id != record.proposed_action_id
                ):
                    raise ValueError("Approval identity cannot change.")
            self._approval_requests[record.approval_id] = record
            return record

    def get_approval_request(self, record_id):
        return self._approval_requests.get(record_id)

    def transition_pending_approval(self, record):
        _validate_terminal_approval(record)
        with self._approval_lock:
            current = self._approval_requests.get(record.approval_id)
            if not _matches_pending_approval(current, record):
                return False
            self._approval_requests[record.approval_id] = record
            return True

    def list_approval_requests(self, status=None):
        records = [
            record
            for record in self._approval_requests.values()
            if status is None or record.status == status
        ]

        return sorted(
            records,
            key=lambda record: (record.requested_at, record.approval_id),
            reverse=True,
        )

    # --- Response actions --------------------------------------------------

    def save_response_action(self, record):
        self._response_actions[record.response_action_id] = record
        return record

    def get_response_action(self, record_id):
        return self._response_actions.get(record_id)

    # --- Action results ----------------------------------------------------

    def save_action_result(self, record):
        self._action_results[record.action_result_id] = record
        return record

    def get_action_result(self, record_id):
        return self._action_results.get(record_id)

    # --- Action verifications ----------------------------------------------

    def save_action_verification(self, record):
        self._action_verifications[record.verification_id] = record

        return record

    def get_action_verification(self, record_id):
        return self._action_verifications.get(record_id)

    # --- Action rollbacks --------------------------------------------------

    def save_action_rollback(self, record):
        self._action_rollbacks[record.rollback_id] = record

        return record

    def get_action_rollback(self, record_id):
        return self._action_rollbacks.get(record_id)

    # --- Incident cases ----------------------------------------------------

    # --- Response history, newest first ------------------------------------

    def list_response_actions(self):
        return sorted(self._response_actions.values(), key=lambda record: (record.created_at, record.response_action_id), reverse=True)

    def list_action_results(self):
        return sorted(self._action_results.values(), key=lambda record: (record.recorded_at, record.action_result_id), reverse=True)

    def list_action_verifications(self):
        return sorted(self._action_verifications.values(), key=lambda record: (record.verified_at, record.verification_id), reverse=True)

    def list_action_rollbacks(self):
        return sorted(self._action_rollbacks.values(), key=lambda record: (record.recorded_at, record.rollback_id), reverse=True)

    def save_incident_case(self, record):
        self._incident_cases[record.case_id] = record

        return record

    def get_incident_case(self, case_id):
        return self._incident_cases.get(case_id)

    def list_incident_cases(self, incident_id):
        records = [
            record
            for record in self._incident_cases.values()
            if (record.incident_id == incident_id)
        ]

        return sorted(records, key=lambda record: (record.created_at, record.case_id))

    def list_all_incident_cases(self):
        return sorted(
            self._incident_cases.values(),
            key=lambda record: (record.created_at, record.case_id),
            reverse=True,
        )
