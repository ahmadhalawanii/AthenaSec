import json

import httpx

from app.services.misp_http_client import (
    HttpMISPClient,
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
                "response": {
                    "Attribute": [
                        {
                            "event_id": "42",
                            "type": "ip-src",
                            "value": "203.0.113.10",
                            "Event": {
                                "id": "42",
                                "info": (
                                    "Known brute-force "
                                    "infrastructure"
                                ),
                                "threat_level_id": "1",
                            },
                        }
                    ]
                }
            },
        )


def test_http_misp_client_queries_indicator_and_returns_match():
    transport = FakeTransport()

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            transport
        )
    )

    client = HttpMISPClient(
        base_url="https://misp.local",
        api_key="test-misp-key",
        http_client=http_client,
    )

    enrichment = client.enrich(
        [
            (
                "ip-src",
                "203.0.113.10",
            )
        ]
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
        str(request.url)
        == (
            "https://misp.local/"
            "attributes/restSearch"
        )
    )

    assert (
        request.headers[
            "Authorization"
        ]
        == "test-misp-key"
    )

    assert (
        request.headers[
            "Accept"
        ]
        == "application/json"
    )

    body = json.loads(
        request.content.decode(
            "utf-8"
        )
    )

    assert body == {
        "returnFormat": "json",
        "type": "ip-src",
        "value": "203.0.113.10",
    }

    assert (
        enrichment.queried_indicators
        == [
            "203.0.113.10",
        ]
    )

    assert len(
        enrichment.matches
    ) == 1

    match = enrichment.matches[0]

    assert (
        match.indicator_type
        == "ip-src"
    )

    assert (
        match.indicator_value
        == "203.0.113.10"
    )

    assert (
        match.event_id
        == "42"
    )

    assert (
        match.event_info
        == (
            "Known brute-force "
            "infrastructure"
        )
    )

    assert (
        match.threat_level
        == "high"
    )


def test_http_misp_client_rejects_http_failure():
    def failing_transport(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=500,
            json={
                "message": "Internal server error",
            },
        )

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            failing_transport
        )
    )

    client = HttpMISPClient(
        base_url="https://misp.local",
        api_key="test-misp-key",
        http_client=http_client,
    )

    try:
        client.enrich(
            [
                (
                    "ip-src",
                    "203.0.113.10",
                )
            ]
        )

        assert False, (
            "Expected MISP HTTP failure "
            "to raise an exception."
        )

    except RuntimeError as exc:
        assert (
            "MISP request failed"
            in str(exc)
        )


def test_http_misp_client_rejects_invalid_json():
    def invalid_json_transport(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            content=b"not-json",
            headers={
                "Content-Type": "application/json",
            },
        )

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            invalid_json_transport
        )
    )

    client = HttpMISPClient(
        base_url="https://misp.local",
        api_key="test-misp-key",
        http_client=http_client,
    )

    try:
        client.enrich(
            [
                (
                    "ip-src",
                    "203.0.113.10",
                )
            ]
        )

        assert False, (
            "Expected invalid MISP JSON "
            "to raise an exception."
        )

    except RuntimeError as exc:
        assert (
            "invalid JSON"
            in str(exc)
        )


def test_http_misp_client_returns_empty_matches():
    def empty_transport(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "response": {
                    "Attribute": [],
                }
            },
        )

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            empty_transport
        )
    )

    client = HttpMISPClient(
        base_url="https://misp.local",
        api_key="test-misp-key",
        http_client=http_client,
    )

    enrichment = client.enrich(
        [
            (
                "ip-src",
                "203.0.113.10",
            )
        ]
    )

    assert (
        enrichment.queried_indicators
        == [
            "203.0.113.10",
        ]
    )

    assert enrichment.matches == []


def test_http_misp_client_maps_unknown_threat_level():
    def unknown_threat_transport(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "event_id": "77",
                            "type": "ip-src",
                            "value": "203.0.113.10",
                            "Event": {
                                "id": "77",
                                "info": (
                                    "Unknown threat level event"
                                ),
                                "threat_level_id": "999",
                            },
                        }
                    ]
                }
            },
        )

    http_client = httpx.Client(
        transport=httpx.MockTransport(
            unknown_threat_transport
        )
    )

    client = HttpMISPClient(
        base_url="https://misp.local",
        api_key="test-misp-key",
        http_client=http_client,
    )

    enrichment = client.enrich(
        [
            (
                "ip-src",
                "203.0.113.10",
            )
        ]
    )

    assert len(
        enrichment.matches
    ) == 1

    assert (
        enrichment.matches[0].threat_level
        == "unknown"
    )