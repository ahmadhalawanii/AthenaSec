import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture(autouse=True)
def isolated_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("ATHENASEC_PERSISTENCE_BACKEND", "sqlite")
    monkeypatch.setenv("ATHENASEC_DB_PATH", str(tmp_path / "cors.db"))
    monkeypatch.delenv("ATHENASEC_CORS_ORIGINS", raising=False)


def _preflight(client, origin):
    return client.options(
        "/health",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )


def test_default_origin_allowed_with_credentials():
    client = TestClient(create_app())

    response = _preflight(client, "http://localhost:5173")

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == "http://localhost:5173"
    )
    assert response.headers["access-control-allow-credentials"] == "true"


def test_unlisted_origin_is_rejected():
    client = TestClient(create_app())

    response = _preflight(client, "https://evil.example")

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_origins_read_from_env(monkeypatch):
    monkeypatch.setenv(
        "ATHENASEC_CORS_ORIGINS",
        "https://a.example, https://b.example/",
    )
    client = TestClient(create_app())

    for origin in ("https://a.example", "https://b.example"):
        response = _preflight(client, origin)
        assert response.headers["access-control-allow-origin"] == origin

    assert _preflight(client, "http://localhost:5173").status_code == 400


def test_wildcard_origin_refused(monkeypatch):
    monkeypatch.setenv("ATHENASEC_CORS_ORIGINS", "*")

    with pytest.raises(ValueError):
        create_app()


def test_wildcard_refused_among_explicit_origins():
    with pytest.raises(ValueError):
        create_app(cors_origins=["https://a.example", "*"])


def test_actual_request_carries_cors_headers():
    client = TestClient(create_app())

    response = client.get(
        "/health", headers={"Origin": "http://localhost:5173"}
    )

    assert (
        response.headers["access-control-allow-origin"]
        == "http://localhost:5173"
    )
