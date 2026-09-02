import sqlite3
from pathlib import Path
from typing import Protocol

from app.schemas import (
    CaseRecord,
    InvestigationResponse,
    ResponseExecutionResult,
    ResponsePlan,
)


class InvestigationStore(Protocol):
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
        self._investigations: dict[
            str,
            InvestigationResponse,
        ] = {}

        self._cases: dict[
            str,
            CaseRecord,
        ] = {}

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