import httpx


class HttpCortexClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        responder_id: str,
        http_client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.responder_id = responder_id
        self.http_client = (
            http_client
            if http_client is not None
            else httpx.Client(
                timeout=30.0
            )
        )

    def run_responder(
        self,
        action: str,
        target: str,
    ) -> dict:
        if action != "block_ip":
            raise ValueError(
                "Unsupported Cortex action: "
                f"{action}"
            )

        response = self.http_client.post(
            (
                f"{self.base_url}/api/responder/"
                f"{self.responder_id}/run"
            ),
            headers={
                "Authorization": (
                    f"Bearer {self.api_key}"
                ),
                "Content-Type": (
                    "application/json"
                ),
            },
            json={
                "data": target,
                "dataType": "ip",
            },
        )

        if response.status_code >= 400:
            raise RuntimeError(
                "Cortex responder request failed "
                f"with HTTP {response.status_code}."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "Cortex returned an invalid "
                "JSON response."
            ) from exc

        if payload.get("success") is False:
            raise RuntimeError(
                "Cortex responder reported failure: "
                f"{payload.get('errorMessage', 'unknown error')}"
            )

        return payload