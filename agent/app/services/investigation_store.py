import sqlite3
from pathlib import Path
from typing import Protocol

from app.schemas import (
    DryRunExecutionResult,
    InvestigationResponse,
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
        execution_result: DryRunExecutionResult,
    ) -> InvestigationResponse:
        ...


class InMemoryInvestigationStore:
    def __init__(self):
        self._investigations: dict[
            str,
            InvestigationResponse,
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
        execution_result: DryRunExecutionResult,
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
        execution_result: DryRunExecutionResult,
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