import os

from app.schemas import (
    MISPEnrichment,
)
from app.services.misp_client import (
    MISPIndicator,
)
from app.services.misp_http_client import (
    HttpMISPClient,
)


class UnavailableMISPClient:
    def __init__(
        self,
        reason: str,
    ):
        self.reason = reason

    def enrich(
        self,
        indicators: list[MISPIndicator],
    ) -> MISPEnrichment:
        raise RuntimeError(
            self.reason
        )


def build_misp_client_from_env() -> HttpMISPClient:
    misp_url = os.getenv(
        "MISP_URL"
    )

    misp_api_key = os.getenv(
        "MISP_API_KEY"
    )

    if (
        misp_url is None
        or not misp_url.strip()
        or misp_api_key is None
        or not misp_api_key.strip()
    ):
        raise RuntimeError(
            "MISP_URL and MISP_API_KEY "
            "must both be configured."
        )

    return HttpMISPClient(
        base_url=misp_url,
        api_key=misp_api_key,
    )


def build_live_misp_client():
    try:
        return build_misp_client_from_env()

    except Exception as exc:
        return UnavailableMISPClient(
            reason=str(
                exc
            )
        )