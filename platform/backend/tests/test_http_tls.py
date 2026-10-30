"""TLS options for MISP and Cortex (self-signed certificates on the AthenaSec server)."""

import ssl

import httpx
import pytest

from app.services.cortex.cortex_client import HttpCortexClient
from app.services.http_tls import tls_verify
from app.services.misp.misp_config import build_misp_client_from_env


def test_checks_certificates_by_default(monkeypatch):
    monkeypatch.delenv("MISP_VERIFY_SSL", raising=False)
    monkeypatch.delenv("MISP_CA_BUNDLE", raising=False)

    assert tls_verify("MISP") is True


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off"])
def test_verify_can_be_switched_off(monkeypatch, value):
    monkeypatch.setenv("CORTEX_VERIFY_SSL", value)

    assert tls_verify("CORTEX") is False


def test_a_ca_bundle_wins(monkeypatch):
    import certifi

    monkeypatch.setenv("MISP_VERIFY_SSL", "false")
    monkeypatch.setenv("MISP_CA_BUNDLE", certifi.where())

    assert isinstance(tls_verify("MISP"), ssl.SSLContext)


def test_misp_client_gets_the_setting(monkeypatch):
    seen = {}
    real = httpx.Client

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "Client", spy)
    monkeypatch.setenv("MISP_URL", "https://localhost:9445")
    monkeypatch.setenv("MISP_API_KEY", "k")
    monkeypatch.setenv("MISP_VERIFY_SSL", "false")

    build_misp_client_from_env()

    assert seen["verify"] is False


def test_cortex_client_default_still_verifies(monkeypatch):
    seen = {}
    real = httpx.Client

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "Client", spy)
    HttpCortexClient(base_url="https://x", api_key="k", responder_id="r")

    assert seen["verify"] is True
