from app.graph.state import InvestigationState
from app.schemas import (
    MISPEnrichment,
)
from app.services.misp_client import (
    MISPClient,
)
from app.services.misp_indicator_extractor import (
    extract_misp_indicators,
)


def make_misp_enrichment_node(
    client: MISPClient,
):
    def enrich_with_misp(
        state: InvestigationState,
    ) -> InvestigationState:
        alert = state["alert"]

        indicators = extract_misp_indicators(
            alert
        )

        queried_indicators = [
            value
            for _, value in indicators
        ]

        try:
            enrichment = client.enrich(
                indicators
            )

        except Exception as exc:
            return {
                "misp_enrichment": (
                    MISPEnrichment(
                        queried_indicators=(
                            queried_indicators
                        ),
                        matches=[],
                    )
                ),
                "misp_error": str(
                    exc
                ),
            }

        return {
            "misp_enrichment": enrichment,
        }

    return enrich_with_misp