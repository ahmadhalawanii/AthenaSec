"""Postgres store. Saves records to PostgreSQL; used in the Docker / production setup."""

import psycopg

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
from app.services.storage.incident_response_store.base import _validate_terminal_approval


class PostgresIncidentResponseStore:
    """Stores records in a PostgreSQL database."""

    # --- Setup -------------------------------------------------------------

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url

        if connect is None:
            connect = psycopg.connect

        self._connect = connect

        self._initialize_database()

    def _initialize_database(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS incident_risk_assessments (
                risk_assessment_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                assessed_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_cases (
                case_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                investigation_id TEXT,
                policy_decision_id TEXT,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS proposed_actions (
                proposed_action_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                proposed_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_risk_assessments (
                action_risk_id TEXT PRIMARY KEY,
                proposed_action_id TEXT NOT NULL,
                assessed_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_policy_decisions (
                decision_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                decided_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS approval_requests (
                approval_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                policy_decision_id TEXT NOT NULL,
                action_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                response_action_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                approval_id TEXT,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_results (
                action_result_id TEXT PRIMARY KEY,
                response_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_verifications (
                verification_id TEXT PRIMARY KEY,
                response_action_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                verified_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_rollbacks (
                rollback_id TEXT PRIMARY KEY,
                response_action_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                verification_id TEXT NOT NULL,
                status TEXT NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
        ]

        with self._connect(self.database_url) as connection:
            for statement in statements:
                connection.execute(statement)

    # --- Shared save / load helpers ----------------------------------------

    def _save(
        self,
        *,
        table,
        id_column,
        id_value,
        columns,
        values,
        payload,
        on_conflict_where=None,
    ):
        column_names = ", ".join([id_column, *columns, "payload"])

        placeholders = ", ".join("%s" for _ in range(len(columns) + 2))

        updates = ", ".join(
            (f"{column} = EXCLUDED.{column}" for column in [*columns, "payload"])
        )

        sql = (
            f"INSERT INTO {table} "
            f"({column_names}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT ({id_column}) "
            f"DO UPDATE SET {updates}"
        )

        if on_conflict_where is not None:
            sql += " WHERE " + on_conflict_where

        with self._connect(self.database_url) as connection:
            connection.execute(sql, (id_value, *values, payload))

    def _get(self, *, table, id_column, id_value, model):
        with self._connect(self.database_url) as connection:
            row = connection.execute(
                (f"SELECT payload FROM {table} WHERE {id_column} = %s"), (id_value,)
            ).fetchone()

        if row is None:
            return None

        return model.model_validate_json(row[0])

    # --- Incident risk assessments -----------------------------------------

    def save_incident_risk(self, record):
        self._save(
            table="incident_risk_assessments",
            id_column="risk_assessment_id",
            id_value=record.risk_assessment_id,
            columns=["incident_id", "investigation_id", "assessed_at"],
            values=[record.incident_id, record.investigation_id, record.assessed_at],
            payload=record.model_dump_json(),
        )
        return record

    def get_incident_risk(self, record_id):
        return self._get(
            table="incident_risk_assessments",
            id_column="risk_assessment_id",
            id_value=record_id,
            model=IncidentRiskAssessmentRecord,
        )

    # --- Proposed actions --------------------------------------------------

    def save_proposed_action(self, record):
        self._save(
            table="proposed_actions",
            id_column="proposed_action_id",
            id_value=record.proposed_action_id,
            columns=["incident_id", "investigation_id", "proposed_at"],
            values=[record.incident_id, record.investigation_id, record.proposed_at],
            payload=record.model_dump_json(),
        )
        return record

    def get_proposed_action(self, record_id):
        return self._get(
            table="proposed_actions",
            id_column="proposed_action_id",
            id_value=record_id,
            model=ProposedActionRecord,
        )

    # --- Action risk assessments -------------------------------------------

    def save_action_risk(self, record):
        self._save(
            table="action_risk_assessments",
            id_column="action_risk_id",
            id_value=record.action_risk_id,
            columns=["proposed_action_id", "assessed_at"],
            values=[record.proposed_action_id, record.assessed_at],
            payload=record.model_dump_json(),
        )
        return record

    def get_action_risk(self, record_id):
        return self._get(
            table="action_risk_assessments",
            id_column="action_risk_id",
            id_value=record_id,
            model=ActionRiskAssessmentRecord,
        )

    # --- Policy decisions --------------------------------------------------

    def save_policy_decision(self, record):
        self._save(
            table="incident_policy_decisions",
            id_column="decision_id",
            id_value=record.decision_id,
            columns=["incident_id", "proposed_action_id", "outcome", "decided_at"],
            values=[
                record.incident_id,
                record.proposed_action_id,
                record.outcome,
                record.decided_at,
            ],
            payload=record.model_dump_json(),
        )
        return record

    def get_policy_decision(self, record_id):
        return self._get(
            table="incident_policy_decisions",
            id_column="decision_id",
            id_value=record_id,
            model=IncidentPolicyDecisionRecord,
        )

    # --- Approval requests -------------------------------------------------

    def save_approval_request(self, record):
        self._save(
            table="approval_requests",
            id_column="approval_id",
            id_value=record.approval_id,
            columns=[
                "incident_id",
                "proposed_action_id",
                "policy_decision_id",
                "action_fingerprint",
                "status",
                "requested_at",
                "expires_at",
            ],
            values=[
                record.incident_id,
                record.proposed_action_id,
                record.policy_decision_id,
                record.action_fingerprint,
                record.status,
                record.requested_at,
                record.expires_at,
            ],
            payload=record.model_dump_json(),
            on_conflict_where=(
                "approval_requests.status = 'PENDING' "
                "AND EXCLUDED.status <> 'PENDING' "
                "AND approval_requests.action_fingerprint = EXCLUDED.action_fingerprint "
                "AND approval_requests.proposed_action_id = EXCLUDED.proposed_action_id "
                "AND approval_requests.policy_decision_id = EXCLUDED.policy_decision_id"
            ),
        )
        return self.get_approval_request(record.approval_id)

    def get_approval_request(self, record_id):
        return self._get(
            table="approval_requests",
            id_column="approval_id",
            id_value=record_id,
            model=ApprovalRequestRecord,
        )

    def transition_pending_approval(self, record):
        _validate_terminal_approval(record)
        sql = (
            "UPDATE approval_requests SET status = %s, payload = %s "
            "WHERE approval_id = %s AND status = 'PENDING' "
            "AND action_fingerprint = %s "
            "AND proposed_action_id = %s "
            "AND policy_decision_id = %s "
            "AND incident_id = %s"
        )
        args = [
            record.status,
            record.model_dump_json(),
            record.approval_id,
            record.action_fingerprint,
            record.proposed_action_id,
            record.policy_decision_id,
            record.incident_id,
        ]
        if record.status == "APPROVED":
            sql += " AND (expires_at IS NULL OR expires_at > %s)"
            args.append(record.decided_at)
        with self._connect(self.database_url) as connection:
            result = connection.execute(sql, tuple(args))
            return result.rowcount == 1

    def list_approval_requests(self, status=None):
        with self._connect(self.database_url) as connection:
            if status is None:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM approval_requests
                    ORDER BY requested_at DESC, approval_id DESC
                    """
                ).fetchall()

            else:
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM approval_requests
                    WHERE status = %s
                    ORDER BY requested_at DESC, approval_id DESC
                    """,
                    (status,),
                ).fetchall()

        return [ApprovalRequestRecord.model_validate_json(row[0]) for row in rows]

    # --- Response actions --------------------------------------------------

    def save_response_action(self, record):
        self._save(
            table="response_actions",
            id_column="response_action_id",
            id_value=record.response_action_id,
            columns=[
                "incident_id",
                "proposed_action_id",
                "approval_id",
                "status",
                "created_at",
            ],
            values=[
                record.incident_id,
                record.proposed_action_id,
                record.approval_id,
                record.status,
                record.created_at,
            ],
            payload=record.model_dump_json(),
        )
        return record

    def get_response_action(self, record_id):
        return self._get(
            table="response_actions",
            id_column="response_action_id",
            id_value=record_id,
            model=ResponseActionRecord,
        )

    # --- Action results ----------------------------------------------------

    def save_action_result(self, record):
        self._save(
            table="action_results",
            id_column="action_result_id",
            id_value=record.action_result_id,
            columns=["response_action_id", "status", "recorded_at"],
            values=[record.response_action_id, record.status, record.recorded_at],
            payload=record.model_dump_json(),
        )
        return record

    def get_action_result(self, record_id):
        return self._get(
            table="action_results",
            id_column="action_result_id",
            id_value=record_id,
            model=ActionExecutionResultRecord,
        )

    # --- Action verifications ----------------------------------------------

    def save_action_verification(self, record):
        self._save(
            table="action_verifications",
            id_column="verification_id",
            id_value=(record.verification_id),
            columns=[
                "response_action_id",
                "proposed_action_id",
                "status",
                "verified_at",
            ],
            values=[
                record.response_action_id,
                record.proposed_action_id,
                record.status,
                record.verified_at,
            ],
            payload=record.model_dump_json(),
        )

        return record

    def get_action_verification(self, record_id):
        return self._get(
            table="action_verifications",
            id_column="verification_id",
            id_value=record_id,
            model=ActionVerificationRecord,
        )

    # --- Action rollbacks --------------------------------------------------

    def save_action_rollback(self, record):
        self._save(
            table="action_rollbacks",
            id_column="rollback_id",
            id_value=record.rollback_id,
            columns=[
                "response_action_id",
                "proposed_action_id",
                "verification_id",
                "status",
                "recorded_at",
            ],
            values=[
                record.response_action_id,
                record.proposed_action_id,
                record.verification_id,
                record.status,
                record.recorded_at,
            ],
            payload=record.model_dump_json(),
        )

        return record

    def get_action_rollback(self, record_id):
        return self._get(
            table="action_rollbacks",
            id_column="rollback_id",
            id_value=record_id,
            model=ActionRollbackRecord,
        )

    # --- Incident cases ----------------------------------------------------

    # --- Response history, newest first ------------------------------------

    def list_response_actions(self):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                "SELECT payload FROM response_actions ORDER BY created_at DESC, response_action_id DESC"
            ).fetchall()

        return [ResponseActionRecord.model_validate_json(row[0]) for row in rows]

    def list_action_results(self):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                "SELECT payload FROM action_results ORDER BY recorded_at DESC, action_result_id DESC"
            ).fetchall()

        return [ActionExecutionResultRecord.model_validate_json(row[0]) for row in rows]

    def list_action_verifications(self):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                "SELECT payload FROM action_verifications ORDER BY verified_at DESC, verification_id DESC"
            ).fetchall()

        return [ActionVerificationRecord.model_validate_json(row[0]) for row in rows]

    def list_action_rollbacks(self):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                "SELECT payload FROM action_rollbacks ORDER BY recorded_at DESC, rollback_id DESC"
            ).fetchall()

        return [ActionRollbackRecord.model_validate_json(row[0]) for row in rows]

    def save_incident_case(self, record):
        self._save(
            table="incident_cases",
            id_column="case_id",
            id_value=record.case_id,
            columns=[
                "incident_id",
                "investigation_id",
                "policy_decision_id",
                "status",
                "created_at",
                "updated_at",
            ],
            values=[
                record.incident_id,
                record.investigation_id,
                record.policy_decision_id,
                record.status,
                record.created_at,
                record.updated_at,
            ],
            payload=record.model_dump_json(),
        )

        return record

    def get_incident_case(self, case_id):
        return self._get(
            table="incident_cases",
            id_column="case_id",
            id_value=case_id,
            model=IncidentCaseRecord,
        )

    def list_incident_cases(self, incident_id):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_cases
                WHERE incident_id = %s
                ORDER BY created_at ASC, case_id ASC
                """,
                (incident_id,),
            ).fetchall()

        return [IncidentCaseRecord.model_validate_json(row[0]) for row in rows]

    def list_all_incident_cases(self):
        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_cases
                ORDER BY created_at DESC, case_id DESC
                """
            ).fetchall()

        return [IncidentCaseRecord.model_validate_json(row[0]) for row in rows]
