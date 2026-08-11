from app.schemas import (
    InvestigationResponse,
    ResponsePlan,
)


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