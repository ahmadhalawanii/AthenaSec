import json

import httpx

from app.services.cortex_client import (
    HttpCortexClient,
)


class FakeTransport:
    def __init__(self):
        self.requests = []

    def __call__(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        self.requests.append(
            request
        )

        return httpx.Response(
            status_code=200,
            json={
                "success": True,
                "full": {
                    "message": (
                        "Responder completed."
                    ),
                },
                "operations": [],
            },
        )


def test_cortex_client_returns_responder_result():
    transport = FakeTransport()

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            transport
        )
    )

    client = HttpCortexClient(
        base_url="http://cortex:9001",
        api_key="test-api-key",
        responder_id="BlockIp_1_0",
        http_client=http_client,
    )

    result = client.run_responder(
        action="block_ip",
        target="203.0.113.50",
    )

    assert len(
        transport.requests
    ) == 1

    request = transport.requests[0]

    assert (
        request.method
        == "POST"
    )

    assert (
        request.headers[
            "Authorization"
        ]
        == "Bearer test-api-key"
    )

    body = json.loads(
        request.content.decode(
            "utf-8"
        )
    )

    assert (
        body["data"]
        == "203.0.113.50"
    )

    assert (
        body["dataType"]
        == "ip"
    )

    assert (
        result["success"]
        is True
    )

    assert (
        result["full"]["message"]
        == "Responder completed."
    )

    assert (
        result["operations"]
        == []
    )

def test_cortex_client_rejects_failed_response():
    def failing_transport(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=500,
            json={
                "success": False,
                "errorMessage": (
                    "Responder failed."
                ),
            },
        )

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            failing_transport
        )
    )

    client = HttpCortexClient(
        base_url="http://cortex:9001",
        api_key="test-api-key",
        responder_id="BlockIp_1_0",
        http_client=http_client,
    )

    try:
        client.run_responder(
            action="block_ip",
            target="203.0.113.50",
        )

        assert False, (
            "Expected Cortex failure "
            "to raise an exception."
        )

    except RuntimeError as exc:
        assert (
            "Cortex"
            in str(exc)
        )