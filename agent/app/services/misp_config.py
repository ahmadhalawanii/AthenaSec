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


def _tls_verify_from_env() -> bool | str:
    ca_bundle = os.getenv(
        "MISP_CA_BUNDLE",
        "",
    ).strip()

    if ca_bundle:
        if not os.path.isfile(
            ca_bundle
        ):
            raise RuntimeError(
                "MISP_CA_BUNDLE does not point "
                "to a readable file."
            )

        return ca_bundle

    raw = os.getenv(
        "MISP_VERIFY_TLS",
        "true",
    ).strip().lower()

    if raw in {"true", "1", "yes"}:
        return True

    if raw in {"false", "0", "no"}:
        return False

    raise RuntimeError(
        "MISP_VERIFY_TLS must be true or false."
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
        verify=_tls_verify_from_env(),
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