import sqlite3
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import (
    ActionExecutionResultRecord,
    ActionRollbackRecord,
    ActionVerificationRecord,
    ActionRiskAssessmentRecord,
    ApprovalRequestRecord,
    IncidentCaseRecord,
    IncidentPolicyDecisionRecord,
    IncidentRiskAssessmentRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)


class IncidentResponseStore(Protocol):
    def save_incident_risk(
        self,
        record: IncidentRiskAssessmentRecord,
    ) -> IncidentRiskAssessmentRecord:
        ...

    def get_incident_risk(
        self,
        record_id: str,
    ) -> IncidentRiskAssessmentRecord | None:
        ...

    def save_proposed_action(
        self,
        record: ProposedActionRecord,
    ) -> ProposedActionRecord:
        ...

    def get_proposed_action(
        self,
        record_id: str,
    ) -> ProposedActionRecord | None:
        ...

    def save_action_risk(
        self,
        record: ActionRiskAssessmentRecord,
    ) -> ActionRiskAssessmentRecord:
        ...

    def get_action_risk(
        self,
        record_id: str,
    ) -> ActionRiskAssessmentRecord | None:
        ...

    def save_policy_decision(
        self,
        record: IncidentPolicyDecisionRecord,
    ) -> IncidentPolicyDecisionRecord:
        ...

    def get_policy_decision(
        self,
        record_id: str,
    ) -> IncidentPolicyDecisionRecord | None:
        ...

    def save_approval_request(
        self,
        record: ApprovalRequestRecord,
    ) -> ApprovalRequestRecord:
        ...

    def get_approval_request(
        self,
        record_id: str,
    ) -> ApprovalRequestRecord | None:
        ...

    def save_response_action(
        self,
        record: ResponseActionRecord,
    ) -> ResponseActionRecord:
        ...

    def get_response_action(
        self,
        record_id: str,
    ) -> ResponseActionRecord | None:
        ...

    def save_action_result(
        self,
        record: ActionExecutionResultRecord,
    ) -> ActionExecutionResultRecord:
        ...

    def get_action_result(
        self,
        record_id: str,
    ) -> ActionExecutionResultRecord | None:
        ...

    def save_action_verification(
        self,
        record: ActionVerificationRecord,
    ) -> ActionVerificationRecord:
        ...

    def get_action_verification(
        self,
        record_id: str,
    ) -> ActionVerificationRecord | None:
        ...


    def save_action_rollback(
        self,
        record: ActionRollbackRecord,
    ) -> ActionRollbackRecord:
        ...

    def get_action_rollback(
        self,
        record_id: str,
    ) -> ActionRollbackRecord | None:
        ...

    def save_incident_case(
        self,
        record: IncidentCaseRecord,
    ) -> IncidentCaseRecord:
        ...

    def get_incident_case(
        self,
        case_id: str,
    ) -> IncidentCaseRecord | None:
        ...

    def list_incident_cases(
        self,
        incident_id: str,
    ) -> list[IncidentCaseRecord]:
        ...


class InMemoryIncidentResponseStore:
    def __init__(self):
        self._incident_risks = {}
        self._proposed_actions = {}
        self._action_risks = {}
        self._policy_decisions = {}
        self._approval_requests = {}
        self._response_actions = {}
        self._action_results = {}
        self._action_verifications = {}
        self._action_rollbacks = {}
        self._incident_cases = {}

    def save_incident_risk(self, record):
        self._incident_risks[
            record.risk_assessment_id
        ] = record
        return record

    def get_incident_risk(self, record_id):
        return self._incident_risks.get(
            record_id
        )

    def save_proposed_action(self, record):
        self._proposed_actions[
            record.proposed_action_id
        ] = record
        return record

    def get_proposed_action(self, record_id):
        return self._proposed_actions.get(
            record_id
        )

    def save_action_risk(self, record):
        self._action_risks[
            record.action_risk_id
        ] = record
        return record

    def get_action_risk(self, record_id):
        return self._action_risks.get(
            record_id
        )

    def save_policy_decision(self, record):
        self._policy_decisions[
            record.decision_id
        ] = record
        return record

    def get_policy_decision(self, record_id):
        return self._policy_decisions.get(
            record_id
        )

    def save_approval_request(self, record):
        self._approval_requests[
            record.approval_id
        ] = record
        return record

    def get_approval_request(self, record_id):
        return self._approval_requests.get(
            record_id
        )

    def save_response_action(self, record):
        self._response_actions[
            record.response_action_id
        ] = record
        return record

    def get_response_action(self, record_id):
        return self._response_actions.get(
            record_id
        )

    def save_action_result(self, record):
        self._action_results[
            record.action_result_id
        ] = record
        return record

    def get_action_result(self, record_id):
        return self._action_results.get(
            record_id
        )

    def save_action_verification(
        self,
        record,
    ):
        self._action_verifications[
            record.verification_id
        ] = record

        return record

    def get_action_verification(
        self,
        record_id,
    ):
        return (
            self._action_verifications
            .get(
                record_id
            )
        )


    def save_action_rollback(
        self,
        record,
    ):
        self._action_rollbacks[
            record.rollback_id
        ] = record

        return record

    def get_action_rollback(
        self,
        record_id,
    ):
        return (
            self._action_rollbacks
            .get(
                record_id
            )
        )

    def save_incident_case(
        self,
        record,
    ):
        self._incident_cases[
            record.case_id
        ] = record

        return record

    def get_incident_case(
        self,
        case_id,
    ):
        return self._incident_cases.get(
            case_id
        )

    def list_incident_cases(
        self,
        incident_id,
    ):
        records = [
            record
            for record
            in self._incident_cases.values()
            if (
                record.incident_id
                == incident_id
            )
        ]

        return sorted(
            records,
            key=lambda record: (
                record.created_at,
                record.case_id,
            ),
        )


class SQLiteIncidentResponseStore:
    def __init__(
        self,
        database_path: str | Path,
    ):
        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(self):
        return sqlite3.connect(
            self.database_path
        )

    def _initialize_database(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS incident_risk_assessments (
                risk_assessment_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS proposed_actions (
                proposed_action_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                proposed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_risk_assessments (
                action_risk_id TEXT PRIMARY KEY,
                proposed_action_id TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_policy_decisions (
                decision_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                decided_at TEXT NOT NULL,
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
                requested_at TEXT NOT NULL,
                expires_at TEXT,
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
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_results (
                action_result_id TEXT PRIMARY KEY,
                response_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS action_verifications (
                verification_id TEXT PRIMARY KEY,
                response_action_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                verified_at TEXT NOT NULL,
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
                recorded_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
        ]

        with self._connect() as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def save_incident_case(
        self,
        record,
    ):
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
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
            ],
            payload=record.model_dump_json(),
        )

        return record

    def get_incident_case(
        self,
        case_id,
    ):
        return self._get(
            table="incident_cases",
            id_column="case_id",
            id_value=case_id,
            model=IncidentCaseRecord,
        )

    def list_incident_cases(
        self,
        incident_id,
    ):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_cases
                WHERE incident_id = ?
                ORDER BY created_at ASC, case_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentCaseRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def _save(
        self,
        *,
        table,
        id_column,
        id_value,
        columns,
        values,
        payload,
    ):
        column_names = ", ".join(
            [
                id_column,
                *columns,
                "payload",
            ]
        )

        placeholders = ", ".join(
            "?"
            for _ in range(
                len(columns) + 2
            )
        )

        updates = ", ".join(
            (
                f"{column} = excluded.{column}"
                for column in [
                    *columns,
                    "payload",
                ]
            )
        )

        sql = (
            f"INSERT INTO {table} "
            f"({column_names}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT ({id_column}) "
            f"DO UPDATE SET {updates}"
        )

        with self._connect() as connection:
            connection.execute(
                sql,
                (
                    id_value,
                    *values,
                    payload,
                ),
            )

    def _get(
        self,
        *,
        table,
        id_column,
        id_value,
        model,
    ):
        with self._connect() as connection:
            row = connection.execute(
                (
                    f"SELECT payload "
                    f"FROM {table} "
                    f"WHERE {id_column} = ?"
                ),
                (
                    id_value,
                ),
            ).fetchone()

        if row is None:
            return None

        return model.model_validate_json(
            row[0]
        )

    def save_incident_risk(self, record):
        self._save(
            table="incident_risk_assessments",
            id_column="risk_assessment_id",
            id_value=record.risk_assessment_id,
            columns=[
                "incident_id",
                "investigation_id",
                "assessed_at",
            ],
            values=[
                record.incident_id,
                record.investigation_id,
                record.assessed_at.isoformat(),
            ],
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

    def save_proposed_action(self, record):
        self._save(
            table="proposed_actions",
            id_column="proposed_action_id",
            id_value=record.proposed_action_id,
            columns=[
                "incident_id",
                "investigation_id",
                "proposed_at",
            ],
            values=[
                record.incident_id,
                record.investigation_id,
                record.proposed_at.isoformat(),
            ],
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

    def save_action_risk(self, record):
        self._save(
            table="action_risk_assessments",
            id_column="action_risk_id",
            id_value=record.action_risk_id,
            columns=[
                "proposed_action_id",
                "assessed_at",
            ],
            values=[
                record.proposed_action_id,
                record.assessed_at.isoformat(),
            ],
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

    def save_policy_decision(self, record):
        self._save(
            table="incident_policy_decisions",
            id_column="decision_id",
            id_value=record.decision_id,
            columns=[
                "incident_id",
                "proposed_action_id",
                "outcome",
                "decided_at",
            ],
            values=[
                record.incident_id,
                record.proposed_action_id,
                record.outcome,
                record.decided_at.isoformat(),
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
                record.requested_at.isoformat(),
                (
                    record.expires_at.isoformat()
                    if record.expires_at
                    else None
                ),
            ],
            payload=record.model_dump_json(),
        )
        return record

    def get_approval_request(self, record_id):
        return self._get(
            table="approval_requests",
            id_column="approval_id",
            id_value=record_id,
            model=ApprovalRequestRecord,
        )

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
                record.created_at.isoformat(),
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

    def save_action_result(self, record):
        self._save(
            table="action_results",
            id_column="action_result_id",
            id_value=record.action_result_id,
            columns=[
                "response_action_id",
                "status",
                "recorded_at",
            ],
            values=[
                record.response_action_id,
                record.status,
                record.recorded_at.isoformat(),
            ],
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

    def save_action_verification(
        self,
        record,
    ):
        self._save(
            table="action_verifications",
            id_column="verification_id",
            id_value=(
                record.verification_id
            ),
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

    def get_action_verification(
        self,
        record_id,
    ):
        return self._get(
            table="action_verifications",
            id_column="verification_id",
            id_value=record_id,
            model=ActionVerificationRecord,
        )


    def save_action_rollback(
        self,
        record,
    ):
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
                record.recorded_at.isoformat(),
            ],
            payload=record.model_dump_json(),
        )

        return record

    def get_action_rollback(
        self,
        record_id,
    ):
        return self._get(
            table="action_rollbacks",
            id_column="rollback_id",
            id_value=record_id,
            model=ActionRollbackRecord,
        )




class PostgresIncidentResponseStore:
    def __init__(
        self,
        database_url: str,
        *,
        connect=None,
    ):
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

        with self._connect(
            self.database_url
        ) as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def save_incident_case(
        self,
        record,
    ):
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

    def get_incident_case(
        self,
        case_id,
    ):
        return self._get(
            table="incident_cases",
            id_column="case_id",
            id_value=case_id,
            model=IncidentCaseRecord,
        )

    def list_incident_cases(
        self,
        incident_id,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_cases
                WHERE incident_id = %s
                ORDER BY created_at ASC, case_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentCaseRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def _save(
        self,
        *,
        table,
        id_column,
        id_value,
        columns,
        values,
        payload,
    ):
        column_names = ", ".join(
            [
                id_column,
                *columns,
                "payload",
            ]
        )

        placeholders = ", ".join(
            "%s"
            for _ in range(
                len(columns) + 2
            )
        )

        updates = ", ".join(
            (
                f"{column} = EXCLUDED.{column}"
                for column in [
                    *columns,
                    "payload",
                ]
            )
        )

        sql = (
            f"INSERT INTO {table} "
            f"({column_names}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT ({id_column}) "
            f"DO UPDATE SET {updates}"
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                sql,
                (
                    id_value,
                    *values,
                    payload,
                ),
            )

    def _get(
        self,
        *,
        table,
        id_column,
        id_value,
        model,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                (
                    f"SELECT payload "
                    f"FROM {table} "
                    f"WHERE {id_column} = %s"
                ),
                (
                    id_value,
                ),
            ).fetchone()

        if row is None:
            return None

        return model.model_validate_json(
            row[0]
        )

    def save_incident_risk(self, record):
        self._save(
            table="incident_risk_assessments",
            id_column="risk_assessment_id",
            id_value=record.risk_assessment_id,
            columns=[
                "incident_id",
                "investigation_id",
                "assessed_at",
            ],
            values=[
                record.incident_id,
                record.investigation_id,
                record.assessed_at,
            ],
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

    def save_proposed_action(self, record):
        self._save(
            table="proposed_actions",
            id_column="proposed_action_id",
            id_value=record.proposed_action_id,
            columns=[
                "incident_id",
                "investigation_id",
                "proposed_at",
            ],
            values=[
                record.incident_id,
                record.investigation_id,
                record.proposed_at,
            ],
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

    def save_action_risk(self, record):
        self._save(
            table="action_risk_assessments",
            id_column="action_risk_id",
            id_value=record.action_risk_id,
            columns=[
                "proposed_action_id",
                "assessed_at",
            ],
            values=[
                record.proposed_action_id,
                record.assessed_at,
            ],
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

    def save_policy_decision(self, record):
        self._save(
            table="incident_policy_decisions",
            id_column="decision_id",
            id_value=record.decision_id,
            columns=[
                "incident_id",
                "proposed_action_id",
                "outcome",
                "decided_at",
            ],
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
        )
        return record

    def get_approval_request(self, record_id):
        return self._get(
            table="approval_requests",
            id_column="approval_id",
            id_value=record_id,
            model=ApprovalRequestRecord,
        )

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

    def save_action_result(self, record):
        self._save(
            table="action_results",
            id_column="action_result_id",
            id_value=record.action_result_id,
            columns=[
                "response_action_id",
                "status",
                "recorded_at",
            ],
            values=[
                record.response_action_id,
                record.status,
                record.recorded_at,
            ],
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

    def save_action_verification(
        self,
        record,
    ):
        self._save(
            table="action_verifications",
            id_column="verification_id",
            id_value=(
                record.verification_id
            ),
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

    def get_action_verification(
        self,
        record_id,
    ):
        return self._get(
            table="action_verifications",
            id_column="verification_id",
            id_value=record_id,
            model=ActionVerificationRecord,
        )


    def save_action_rollback(
        self,
        record,
    ):
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

    def get_action_rollback(
        self,
        record_id,
    ):
        return self._get(
            table="action_rollbacks",
            id_column="rollback_id",
            id_value=record_id,
            model=ActionRollbackRecord,
        )
