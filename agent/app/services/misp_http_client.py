import httpx

from app.schemas import (
    MISPEnrichment,
    MISPMatch,
)
from app.services.misp_client import (
    MISPIndicator,
)


THREAT_LEVEL_MAP = {
    "1": "high",
    "2": "medium",
    "3": "low",
    "4": "unknown",
}


class HttpMISPClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        http_client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.http_client = (
            http_client
            if http_client is not None
            else httpx.Client(
                timeout=30.0
            )
        )

    def enrich(
        self,
        indicators: list[MISPIndicator],
    ) -> MISPEnrichment:
        queried_indicators: list[str] = []
        matches: list[MISPMatch] = []

        for (
            indicator_type,
            indicator_value,
        ) in indicators:
            queried_indicators.append(
                indicator_value
            )

            response = self.http_client.post(
                (
                    f"{self.base_url}/"
                    "attributes/restSearch"
                ),
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": (
                        "application/json"
                    ),
                },
                json={
                    "returnFormat": "json",
                    "type": indicator_type,
                    "value": indicator_value,
                },
            )

            if response.status_code >= 400:
                raise RuntimeError(
                    "MISP request failed with "
                    f"status {response.status_code}."
                )

            try:
                payload = response.json()
            except ValueError as exc:
                raise RuntimeError(
                    "MISP returned invalid JSON."
                ) from exc

            attributes = (
                payload.get(
                    "response",
                    {},
                ).get(
                    "Attribute",
                    [],
                )
            )

            if not isinstance(
                attributes,
                list,
            ):
                raise RuntimeError(
                    "MISP response contains an "
                    "invalid Attribute payload."
                )

            for attribute in attributes:
                event = attribute.get(
                    "Event",
                    {},
                )

                threat_level_id = str(
                    event.get(
                        "threat_level_id",
                        "4",
                    )
                )

                matches.append(
                    MISPMatch(
                        indicator_type=str(
                            attribute.get(
                                "type",
                                indicator_type,
                            )
                        ),
                        indicator_value=str(
                            attribute.get(
                                "value",
                                indicator_value,
                            )
                        ),
                        event_id=str(
                            attribute.get(
                                "event_id",
                                event.get(
                                    "id",
                                    "",
                                ),
                            )
                        ),
                        event_info=str(
                            event.get(
                                "info",
                                "",
                            )
                        ),
                        threat_level=(
                            THREAT_LEVEL_MAP.get(
                                threat_level_id,
                                "unknown",
                            )
                        ),
                    )
                )

        return MISPEnrichment(
            queried_indicators=queried_indicators,
            matches=matches,
        )