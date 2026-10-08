import sqlite3
import psycopg
from datetime import (
    datetime,
    timedelta,
)
from pathlib import Path
from typing import Protocol

from app.schemas import (
    AttackClassification,
    CaseRecord,
    IncidentAlertRecord,
    IncidentCorrelationProfile,
    IncidentInvestigationRecord,
    IncidentRecord,
    InvestigationEvidenceRecord,
    InvestigationResponse,
    ResponseExecutionResult,
    ResponsePlan,
    InvestigationStepRecord,
)

class InvestigationStore(Protocol):
    def save_incident(
        self,
        incident: IncidentRecord,
    ) -> IncidentRecord:
        ...

    def get_incident(
        self,
        incident_id: str,
    ) -> IncidentRecord | None:
        ...

    def save_correlation_profile(
        self,
        profile: IncidentCorrelationProfile,
    ) -> IncidentCorrelationProfile:
        ...

    def get_correlation_profile(
        self,
        incident_id: str,
    ) -> IncidentCorrelationProfile | None:
        ...

    def list_correlation_candidates(
        self,
        *,
        classification: AttackClassification,
        observed_at: datetime,
        window: timedelta,
    ) -> list[IncidentCorrelationProfile]:
        ...

    def save_incident_alert(
        self,
        alert: IncidentAlertRecord,
    ) -> IncidentAlertRecord:
        ...

    def get_incident_alert(
        self,
        alert_id: str,
    ) -> IncidentAlertRecord | None:
        ...

    def list_incident_alerts(
        self,
        incident_id: str,
    ) -> list[IncidentAlertRecord]:
        ...

    def save_incident_investigation(
        self,
        investigation: IncidentInvestigationRecord,
    ) -> IncidentInvestigationRecord:
        ...

    def get_incident_investigation(
        self,
        investigation_id: str,
    ) -> IncidentInvestigationRecord | None:
        ...

    def list_incident_investigations(
        self,
        incident_id: str,
    ) -> list[IncidentInvestigationRecord]:
        ...

    def save_investigation_evidence(
        self,
        evidence: InvestigationEvidenceRecord,
    ) -> InvestigationEvidenceRecord:
        ...

    def get_investigation_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
    ) -> InvestigationEvidenceRecord | None:
        ...

    def list_investigation_evidence(
        self,
        investigation_id: str,
    ) -> list[InvestigationEvidenceRecord]:
        ...

    def save_investigation_step(
        self,
        step: InvestigationStepRecord,
    ) -> InvestigationStepRecord:
        ...

    def get_investigation_step(
        self,
        investigation_id: str,
        step_id: str,
    ) -> InvestigationStepRecord | None:
        ...

    def list_investigation_steps(
        self,
        investigation_id: str,
    ) -> list[InvestigationStepRecord]:
        ...

    def save(
        self,
        investigation: InvestigationResponse,
    ) -> InvestigationResponse:
        ...

    def get(
        self,
        alert_id: str,
    ) -> InvestigationResponse | None:
        ...

    def update_response_plan(
        self,
        alert_id: str,
        response_plan: ResponsePlan,
    ) -> InvestigationResponse:
        ...

    def update_execution_result(
        self,
        alert_id: str,
        execution_result: ResponseExecutionResult,
    ) -> InvestigationResponse:
        ...

    def save_case(
        self,
        case: CaseRecord,
    ) -> CaseRecord:
        ...

    def get_case(
        self,
        case_id: str,
    ) -> CaseRecord | None:
        ...

    def get_case_by_alert_id(
        self,
        alert_id: str,
    ) -> CaseRecord | None:
        ...


class InMemoryInvestigationStore:
    def __init__(self):
        self._incidents: dict[
            str,
            IncidentRecord,
        ] = {}

        self._incident_alerts: dict[
            str,
            IncidentAlertRecord,
        ] = {}

        self._incident_investigations: dict[
            str,
            IncidentInvestigationRecord,
        ] = {}

        self._investigation_evidence: dict[
            tuple[str, str],
            InvestigationEvidenceRecord,
        ] = {}

        self._investigation_steps: dict[
            tuple[str, str],
            InvestigationStepRecord,
        ] = {}

        self._investigations: dict[
            str,
            InvestigationResponse,
        ] = {}

        self._cases: dict[
            str,
            CaseRecord,
        ] = {}

        self._correlation_profiles: dict[
            str,
            IncidentCorrelationProfile,
        ] = {}

    def save_incident(
        self,
        incident: IncidentRecord,
    ) -> IncidentRecord:
        self._incidents[
            incident.incident_id
        ] = incident

        return incident

    def get_incident(
        self,
        incident_id: str,
    ) -> IncidentRecord | None:
        return self._incidents.get(
            incident_id
        )

    def save_correlation_profile(
        self,
        profile: IncidentCorrelationProfile,
    ) -> IncidentCorrelationProfile:
        self._correlation_profiles[
            profile.incident_id
        ] = profile

        return profile

    def get_correlation_profile(
        self,
        incident_id: str,
    ) -> IncidentCorrelationProfile | None:
        return self._correlation_profiles.get(
            incident_id
        )

    def list_correlation_candidates(
        self,
        *,
        classification: AttackClassification,
        observed_at: datetime,
        window: timedelta,
    ) -> list[IncidentCorrelationProfile]:
        earliest_allowed = (
            observed_at
            - window
        )

        latest_allowed = (
            observed_at
            + window
        )

        candidates = [
            profile
            for profile
            in self._correlation_profiles.values()
            if (
                profile.classification
                == classification
                and profile.first_seen
                <= latest_allowed
                and profile.last_seen
                >= earliest_allowed
            )
        ]

        return sorted(
            candidates,
            key=lambda profile: (
                -profile.last_seen.timestamp(),
                profile.incident_id,
            ),
        )

    def save_incident_alert(
        self,
        alert: IncidentAlertRecord,
    ) -> IncidentAlertRecord:
        self._incident_alerts[
            alert.alert_id
        ] = alert

        return alert

    def get_incident_alert(
        self,
        alert_id: str,
    ) -> IncidentAlertRecord | None:
        return self._incident_alerts.get(
            alert_id
        )

    def list_incident_alerts(
        self,
        incident_id: str,
    ) -> list[IncidentAlertRecord]:
        alerts = [
            alert
            for alert in self._incident_alerts.values()
            if alert.incident_id == incident_id
        ]

        return sorted(
            alerts,
            key=lambda alert: (
                alert.observed_at,
                alert.alert_id,
            ),
        )

    def save_incident_investigation(
        self,
        investigation: IncidentInvestigationRecord,
    ) -> IncidentInvestigationRecord:
        self._incident_investigations[
            investigation.investigation_id
        ] = investigation

        return investigation

    def get_incident_investigation(
        self,
        investigation_id: str,
    ) -> IncidentInvestigationRecord | None:
        return self._incident_investigations.get(
            investigation_id
        )

    def list_incident_investigations(
        self,
        incident_id: str,
    ) -> list[IncidentInvestigationRecord]:
        investigations = [
            investigation
            for investigation
            in self._incident_investigations.values()
            if investigation.incident_id == incident_id
        ]

        return sorted(
            investigations,
            key=lambda investigation: (
                investigation.started_at,
                investigation.investigation_id,
            ),
        )

    def save_investigation_evidence(
        self,
        evidence: InvestigationEvidenceRecord,
    ) -> InvestigationEvidenceRecord:
        key = (
            evidence.investigation_id,
            evidence.evidence_id,
        )

        self._investigation_evidence[
            key
        ] = evidence

        return evidence

    def get_investigation_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
    ) -> InvestigationEvidenceRecord | None:
        return self._investigation_evidence.get(
            (
                investigation_id,
                evidence_id,
            )
        )

    def list_investigation_evidence(
        self,
        investigation_id: str,
    ) -> list[InvestigationEvidenceRecord]:
        evidence = [
            record
            for (
                stored_investigation_id,
                _,
            ), record
            in self._investigation_evidence.items()
            if (
                stored_investigation_id
                == investigation_id
            )
        ]

        return sorted(
            evidence,
            key=lambda record: (
                record.captured_at,
                record.evidence_id,
            ),
        )

    def save_investigation_step(
        self,
        step: InvestigationStepRecord,
    ) -> InvestigationStepRecord:
        key = (
            step.investigation_id,
            step.step_id,
        )

        self._investigation_steps[
            key
        ] = step

        return step

    def get_investigation_step(
        self,
        investigation_id: str,
        step_id: str,
    ) -> InvestigationStepRecord | None:
        return self._investigation_steps.get(
            (
                investigation_id,
                step_id,
            )
        )

    def list_investigation_steps(
        self,
        investigation_id: str,
    ) -> list[InvestigationStepRecord]:
        steps = [
            record
            for (
                stored_investigation_id,
                _,
            ), record
            in self._investigation_steps.items()
            if (
                stored_investigation_id
                == investigation_id
            )
        ]

        return sorted(
            steps,
            key=lambda record: (
                record.sequence,
                record.step_id,
            ),
        )

    def save(
        self,
        investigation: InvestigationResponse,
    ) -> InvestigationResponse:
        self._investigations[
            investigation.alert_id
        ] = investigation

        return investigation

    def get(
        self,
        alert_id: str,
    ) -> InvestigationResponse | None:
        return self._investigations.get(
            alert_id
        )

    def update_response_plan(
        self,
        alert_id: str,
        response_plan: ResponsePlan,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "response_plan": response_plan,
            }
        )

        self._investigations[
            alert_id
        ] = updated

        return updated

    def update_execution_result(
        self,
        alert_id: str,
        execution_result: ResponseExecutionResult,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "execution_result": execution_result,
            }
        )

        self._investigations[
            alert_id
        ] = updated

        return updated

    def save_case(
        self,
        case: CaseRecord,
    ) -> CaseRecord:
        self._cases[
            case.case_id
        ] = case

        return case

    def get_case(
        self,
        case_id: str,
    ) -> CaseRecord | None:
        return self._cases.get(
            case_id
        )

    def get_case_by_alert_id(
        self,
        alert_id: str,
    ) -> CaseRecord | None:
        for case in self._cases.values():
            if case.alert_id == alert_id:
                return case

        return None


class SQLiteInvestigationStore:
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

    def _connect(
        self,
    ) -> sqlite3.Connection:
        return sqlite3.connect(
            self.database_path
        )

    def _initialize_database(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    alert_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_investigations (
                    investigation_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    primary_alert_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY (primary_alert_id)
                        REFERENCES incident_alerts(alert_id)
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_investigations_incident_id
                ON incident_investigations(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_investigations_started_at
                ON incident_investigations(started_at)
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_evidence (
                    investigation_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (
                        investigation_id,
                        evidence_id
                    ),
                    FOREIGN KEY (investigation_id)
                        REFERENCES incident_investigations(
                            investigation_id
                        )
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_steps (
                    step_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    step_type TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE (
                        investigation_id,
                        sequence
                    ),
                    FOREIGN KEY (investigation_id)
                        REFERENCES incident_investigations(
                            investigation_id
                        )
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_investigation_steps_investigation_id
                ON investigation_steps(
                    investigation_id
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_investigation_evidence_captured_at
                ON investigation_evidence(captured_at)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_alerts_incident_id
                ON incident_alerts(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_alerts_observed_at
                ON incident_alerts(observed_at)
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    alert_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                incident_correlation_profiles (
                    incident_id TEXT PRIMARY KEY,
                    classification TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_correlation_profiles_lookup
                ON incident_correlation_profiles(
                    classification,
                    last_seen,
                    first_seen
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL
                )
                """
            )

    def save_incident(
        self,
        incident: IncidentRecord,
    ) -> IncidentRecord:
        payload = incident.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id,
                    payload
                )
                VALUES (?, ?)
                """,
                (
                    incident.incident_id,
                    payload,
                ),
            )

        return incident

    def get_incident(
        self,
        incident_id: str,
    ) -> IncidentRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incidents
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return IncidentRecord.model_validate_json(
            row[0]
        )

    def save_correlation_profile(
        self,
        profile: IncidentCorrelationProfile,
    ) -> IncidentCorrelationProfile:
        payload = (
            profile.model_dump_json()
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incident_correlation_profiles (
                    incident_id,
                    classification,
                    first_seen,
                    last_seen,
                    payload
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (incident_id)
                DO UPDATE SET
                    classification = excluded.classification,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    payload = excluded.payload
                """,
                (
                    profile.incident_id,
                    profile.classification,
                    profile.first_seen.isoformat(),
                    profile.last_seen.isoformat(),
                    payload,
                ),
            )

        return profile

    def get_correlation_profile(
        self,
        incident_id: str,
    ) -> IncidentCorrelationProfile | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_correlation_profiles
                WHERE incident_id = ?
                """,
                (
                    incident_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentCorrelationProfile
            .model_validate_json(
                row[0]
            )
        )

    def list_correlation_candidates(
        self,
        *,
        classification: AttackClassification,
        observed_at: datetime,
        window: timedelta,
    ) -> list[IncidentCorrelationProfile]:
        earliest_allowed = (
            observed_at
            - window
        )

        latest_allowed = (
            observed_at
            + window
        )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_correlation_profiles
                WHERE classification = ?
                AND first_seen <= ?
                AND last_seen >= ?
                ORDER BY last_seen DESC, incident_id ASC
                """,
                (
                    classification,
                    latest_allowed.isoformat(),
                    earliest_allowed.isoformat(),
                ),
            ).fetchall()

        return [
            (
                IncidentCorrelationProfile
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_incident_alert(
        self,
        alert: IncidentAlertRecord,
    ) -> IncidentAlertRecord:
        payload = alert.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incident_alerts (
                    alert_id,
                    incident_id,
                    observed_at,
                    payload
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.incident_id,
                    alert.observed_at.isoformat(),
                    payload,
                ),
            )

        return alert

    def get_incident_alert(
        self,
        alert_id: str,
    ) -> IncidentAlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_alerts
                WHERE alert_id = ?
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return IncidentAlertRecord.model_validate_json(
            row[0]
        )

    def list_incident_alerts(
        self,
        incident_id: str,
    ) -> list[IncidentAlertRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_alerts
                WHERE incident_id = ?
                ORDER BY observed_at ASC, alert_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentAlertRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def save_incident_investigation(
        self,
        investigation: IncidentInvestigationRecord,
    ) -> IncidentInvestigationRecord:
        payload = (
            investigation.model_dump_json()
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incident_investigations (
                    investigation_id,
                    incident_id,
                    primary_alert_id,
                    started_at,
                    updated_at,
                    payload
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation.investigation_id,
                    investigation.incident_id,
                    investigation.primary_alert_id,
                    investigation.started_at.isoformat(),
                    investigation.updated_at.isoformat(),
                    payload,
                ),
            )

        return investigation

    def get_incident_investigation(
        self,
        investigation_id: str,
    ) -> IncidentInvestigationRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_investigations
                WHERE investigation_id = ?
                """,
                (
                    investigation_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentInvestigationRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_incident_investigations(
        self,
        incident_id: str,
    ) -> list[IncidentInvestigationRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_investigations
                WHERE incident_id = ?
                ORDER BY started_at ASC, investigation_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            (
                IncidentInvestigationRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_investigation_evidence(
        self,
        evidence: InvestigationEvidenceRecord,
    ) -> InvestigationEvidenceRecord:
        payload = evidence.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO investigation_evidence (
                    investigation_id,
                    evidence_id,
                    captured_at,
                    payload
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    evidence.investigation_id,
                    evidence.evidence_id,
                    evidence.captured_at.isoformat(),
                    payload,
                ),
            )

        return evidence

    def get_investigation_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
    ) -> InvestigationEvidenceRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigation_evidence
                WHERE investigation_id = ?
                AND evidence_id = ?
                """,
                (
                    investigation_id,
                    evidence_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            InvestigationEvidenceRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_investigation_evidence(
        self,
        investigation_id: str,
    ) -> list[InvestigationEvidenceRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM investigation_evidence
                WHERE investigation_id = ?
                ORDER BY captured_at ASC, evidence_id ASC
                """,
                (
                    investigation_id,
                ),
            ).fetchall()

        return [
            (
                InvestigationEvidenceRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_investigation_step(
        self,
        step: InvestigationStepRecord,
    ) -> InvestigationStepRecord:
        payload = step.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO investigation_steps (
                    step_id,
                    investigation_id,
                    sequence,
                    step_type,
                    recorded_at,
                    payload
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    step.step_id,
                    step.investigation_id,
                    step.sequence,
                    step.step_type,
                    step.recorded_at.isoformat(),
                    payload,
                ),
            )

        return step

    def get_investigation_step(
        self,
        investigation_id: str,
        step_id: str,
    ) -> InvestigationStepRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigation_steps
                WHERE investigation_id = ?
                AND step_id = ?
                """,
                (
                    investigation_id,
                    step_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            InvestigationStepRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_investigation_steps(
        self,
        investigation_id: str,
    ) -> list[InvestigationStepRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM investigation_steps
                WHERE investigation_id = ?
                ORDER BY sequence ASC, step_id ASC
                """,
                (
                    investigation_id,
                ),
            ).fetchall()

        return [
            (
                InvestigationStepRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save(
        self,
        investigation: InvestigationResponse,
    ) -> InvestigationResponse:
        payload = investigation.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO investigations (
                    alert_id,
                    payload
                )
                VALUES (?, ?)
                """,
                (
                    investigation.alert_id,
                    payload,
                ),
            )

        return investigation

    def get(
        self,
        alert_id: str,
    ) -> InvestigationResponse | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigations
                WHERE alert_id = ?
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return InvestigationResponse.model_validate_json(
            row[0]
        )

    def update_response_plan(
        self,
        alert_id: str,
        response_plan: ResponsePlan,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "response_plan": response_plan,
            }
        )

        return self.save(
            updated
        )

    def update_execution_result(
        self,
        alert_id: str,
        execution_result: ResponseExecutionResult,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "execution_result": execution_result,
            }
        )

        return self.save(
            updated
        )

    def save_case(
        self,
        case: CaseRecord,
    ) -> CaseRecord:
        payload = case.model_dump_json()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO cases (
                    case_id,
                    alert_id,
                    payload
                )
                VALUES (?, ?, ?)
                """,
                (
                    case.case_id,
                    case.alert_id,
                    payload,
                ),
            )

        return case

    def get_case(
        self,
        case_id: str,
    ) -> CaseRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM cases
                WHERE case_id = ?
                """,
                (
                    case_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return CaseRecord.model_validate_json(
            row[0]
        )

    def get_case_by_alert_id(
        self,
        alert_id: str,
    ) -> CaseRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM cases
                WHERE alert_id = ?
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return CaseRecord.model_validate_json(
            row[0]
        )

class PostgresInvestigationStore:
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

    def _initialize_database(
        self,
    ) -> None:
        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    alert_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_investigations (
                    investigation_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    primary_alert_id TEXT NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY (primary_alert_id)
                        REFERENCES incident_alerts(alert_id)
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_investigations_incident_id
                ON incident_investigations(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_investigations_started_at
                ON incident_investigations(started_at)
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_evidence (
                    investigation_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    captured_at TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (
                        investigation_id,
                        evidence_id
                    ),
                    FOREIGN KEY (investigation_id)
                        REFERENCES incident_investigations(
                            investigation_id
                        )
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_steps (
                    step_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    step_type TEXT NOT NULL,
                    recorded_at TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE (
                        investigation_id,
                        sequence
                    ),
                    FOREIGN KEY (investigation_id)
                        REFERENCES incident_investigations(
                            investigation_id
                        )
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_investigation_steps_investigation_id
                ON investigation_steps(
                    investigation_id
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_investigation_evidence_captured_at
                ON investigation_evidence(captured_at)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_alerts_incident_id
                ON incident_alerts(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_alerts_observed_at
                ON incident_alerts(observed_at)
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    alert_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                incident_correlation_profiles (
                    incident_id TEXT PRIMARY KEY,
                    classification TEXT NOT NULL,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_correlation_profiles_lookup
                ON incident_correlation_profiles(
                    classification,
                    last_seen,
                    first_seen
                )
                """
            )

    def save_incident(
        self,
        incident: IncidentRecord,
    ) -> IncidentRecord:
        payload = (
            incident.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id,
                    payload
                )
                VALUES (%s, %s)
                ON CONFLICT (incident_id)
                DO UPDATE SET
                    payload = EXCLUDED.payload
                """,
                (
                    incident.incident_id,
                    payload,
                ),
            )

        return incident

    def get_incident(
        self,
        incident_id: str,
    ) -> IncidentRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incidents
                WHERE incident_id = %s
                """,
                (
                    incident_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentRecord
            .model_validate_json(
                row[0]
            )
        )

    def save_correlation_profile(
        self,
        profile: IncidentCorrelationProfile,
    ) -> IncidentCorrelationProfile:
        payload = (
            profile.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO incident_correlation_profiles (
                    incident_id,
                    classification,
                    first_seen,
                    last_seen,
                    payload
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (incident_id)
                DO UPDATE SET
                    classification = EXCLUDED.classification,
                    first_seen = EXCLUDED.first_seen,
                    last_seen = EXCLUDED.last_seen,
                    payload = EXCLUDED.payload
                """,
                (
                    profile.incident_id,
                    profile.classification,
                    profile.first_seen,
                    profile.last_seen,
                    payload,
                ),
            )

        return profile

    def get_correlation_profile(
        self,
        incident_id: str,
    ) -> IncidentCorrelationProfile | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_correlation_profiles
                WHERE incident_id = %s
                """,
                (
                    incident_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentCorrelationProfile
            .model_validate_json(
                row[0]
            )
        )

    def list_correlation_candidates(
        self,
        *,
        classification: AttackClassification,
        observed_at: datetime,
        window: timedelta,
    ) -> list[IncidentCorrelationProfile]:
        earliest_allowed = (
            observed_at
            - window
        )

        latest_allowed = (
            observed_at
            + window
        )

        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_correlation_profiles
                WHERE classification = %s
                AND first_seen <= %s
                AND last_seen >= %s
                ORDER BY last_seen DESC, incident_id ASC
                """,
                (
                    classification,
                    latest_allowed,
                    earliest_allowed,
                ),
            ).fetchall()

        return [
            (
                IncidentCorrelationProfile
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_incident_alert(
        self,
        alert: IncidentAlertRecord,
    ) -> IncidentAlertRecord:
        payload = (
            alert.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO incident_alerts (
                    alert_id,
                    incident_id,
                    observed_at,
                    payload
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (alert_id)
                DO UPDATE SET
                    incident_id = EXCLUDED.incident_id,
                    observed_at = EXCLUDED.observed_at,
                    payload = EXCLUDED.payload
                """,
                (
                    alert.alert_id,
                    alert.incident_id,
                    alert.observed_at,
                    payload,
                ),
            )

        return alert

    def get_incident_alert(
        self,
        alert_id: str,
    ) -> IncidentAlertRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_alerts
                WHERE alert_id = %s
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentAlertRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_incident_alerts(
        self,
        incident_id: str,
    ) -> list[IncidentAlertRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_alerts
                WHERE incident_id = %s
                ORDER BY observed_at ASC, alert_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentAlertRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def save_incident_investigation(
        self,
        investigation: IncidentInvestigationRecord,
    ) -> IncidentInvestigationRecord:
        payload = (
            investigation.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO incident_investigations (
                    investigation_id,
                    incident_id,
                    primary_alert_id,
                    started_at,
                    updated_at,
                    payload
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (investigation_id)
                DO UPDATE SET
                    incident_id = EXCLUDED.incident_id,
                    primary_alert_id = EXCLUDED.primary_alert_id,
                    started_at = EXCLUDED.started_at,
                    updated_at = EXCLUDED.updated_at,
                    payload = EXCLUDED.payload
                """,
                (
                    investigation.investigation_id,
                    investigation.incident_id,
                    investigation.primary_alert_id,
                    investigation.started_at,
                    investigation.updated_at,
                    payload,
                ),
            )

        return investigation

    def get_incident_investigation(
        self,
        investigation_id: str,
    ) -> IncidentInvestigationRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_investigations
                WHERE investigation_id = %s
                """,
                (
                    investigation_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentInvestigationRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_incident_investigations(
        self,
        incident_id: str,
    ) -> list[IncidentInvestigationRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY started_at ASC, investigation_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            (
                IncidentInvestigationRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_investigation_evidence(
        self,
        evidence: InvestigationEvidenceRecord,
    ) -> InvestigationEvidenceRecord:
        payload = (
            evidence.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO investigation_evidence (
                    investigation_id,
                    evidence_id,
                    captured_at,
                    payload
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (
                    investigation_id,
                    evidence_id
                )
                DO UPDATE SET
                    captured_at = EXCLUDED.captured_at,
                    payload = EXCLUDED.payload
                """,
                (
                    evidence.investigation_id,
                    evidence.evidence_id,
                    evidence.captured_at,
                    payload,
                ),
            )

        return evidence

    def get_investigation_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
    ) -> InvestigationEvidenceRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigation_evidence
                WHERE investigation_id = %s
                AND evidence_id = %s
                """,
                (
                    investigation_id,
                    evidence_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            InvestigationEvidenceRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_investigation_evidence(
        self,
        investigation_id: str,
    ) -> list[InvestigationEvidenceRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM investigation_evidence
                WHERE investigation_id = %s
                ORDER BY captured_at ASC, evidence_id ASC
                """,
                (
                    investigation_id,
                ),
            ).fetchall()

        return [
            (
                InvestigationEvidenceRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save_investigation_step(
        self,
        step: InvestigationStepRecord,
    ) -> InvestigationStepRecord:
        payload = step.model_dump_json()

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO investigation_steps (
                    step_id,
                    investigation_id,
                    sequence,
                    step_type,
                    recorded_at,
                    payload
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (step_id)
                DO UPDATE SET
                    investigation_id = EXCLUDED.investigation_id,
                    sequence = EXCLUDED.sequence,
                    step_type = EXCLUDED.step_type,
                    recorded_at = EXCLUDED.recorded_at,
                    payload = EXCLUDED.payload
                """,
                (
                    step.step_id,
                    step.investigation_id,
                    step.sequence,
                    step.step_type,
                    step.recorded_at,
                    payload,
                ),
            )

        return step

    def get_investigation_step(
        self,
        investigation_id: str,
        step_id: str,
    ) -> InvestigationStepRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigation_steps
                WHERE investigation_id = %s
                AND step_id = %s
                """,
                (
                    investigation_id,
                    step_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            InvestigationStepRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_investigation_steps(
        self,
        investigation_id: str,
    ) -> list[InvestigationStepRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM investigation_steps
                WHERE investigation_id = %s
                ORDER BY sequence ASC, step_id ASC
                """,
                (
                    investigation_id,
                ),
            ).fetchall()

        return [
            (
                InvestigationStepRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]

    def save(
        self,
        investigation: InvestigationResponse,
    ) -> InvestigationResponse:
        payload = (
            investigation.model_dump_json()
        )

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO investigations (
                    alert_id,
                    payload
                )
                VALUES (%s, %s)
                ON CONFLICT (alert_id)
                DO UPDATE SET
                    payload = EXCLUDED.payload
                """,
                (
                    investigation.alert_id,
                    payload,
                ),
            )

        return investigation

    def get(
        self,
        alert_id: str,
    ) -> InvestigationResponse | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM investigations
                WHERE alert_id = %s
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            InvestigationResponse
            .model_validate_json(
                row[0]
            )
        )

    def update_response_plan(
        self,
        alert_id: str,
        response_plan: ResponsePlan,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "response_plan": response_plan,
            }
        )

        return self.save(
            updated
        )

    def update_execution_result(
        self,
        alert_id: str,
        execution_result: ResponseExecutionResult,
    ) -> InvestigationResponse:
        investigation = self.get(
            alert_id
        )

        if investigation is None:
            raise KeyError(
                f"Investigation {alert_id} was not found."
            )

        updated = investigation.model_copy(
            update={
                "execution_result": execution_result,
            }
        )

        return self.save(
            updated
        )

    def save_case(
        self,
        case: CaseRecord,
    ) -> CaseRecord:
        payload = case.model_dump_json()

        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id,
                    alert_id,
                    payload
                )
                VALUES (%s, %s, %s)
                ON CONFLICT (case_id)
                DO UPDATE SET
                    alert_id = EXCLUDED.alert_id,
                    payload = EXCLUDED.payload
                """,
                (
                    case.case_id,
                    case.alert_id,
                    payload,
                ),
            )

        return case

    def get_case(
        self,
        case_id: str,
    ) -> CaseRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM cases
                WHERE case_id = %s
                """,
                (
                    case_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            CaseRecord
            .model_validate_json(
                row[0]
            )
        )

    def get_case_by_alert_id(
        self,
        alert_id: str,
    ) -> CaseRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM cases
                WHERE alert_id = %s
                """,
                (
                    alert_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            CaseRecord
            .model_validate_json(
                row[0]
            )
        )