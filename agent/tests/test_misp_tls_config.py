import pytest

from app.services.misp_config import (
    build_misp_client_from_env,
)


def _env(monkeypatch, **extra):
    monkeypatch.setenv("MISP_URL", "https://127.0.0.1:9445")
    monkeypatch.setenv("MISP_API_KEY", "k")
    for name in ("MISP_CA_BUNDLE", "MISP_VERIFY_TLS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in extra.items():
        monkeypatch.setenv(name, value)


def test_default_verifies_tls(monkeypatch):
    _env(monkeypatch)
    client = build_misp_client_from_env()
    assert client.http_client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"


def test_ca_bundle_is_used(monkeypatch, tmp_path):
    import subprocess
    pem = tmp_path / "ca.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(tmp_path / "k.pem"), "-out", str(pem),
         "-days", "1", "-subj", "/CN=misp-test"],
        check=True, capture_output=True,
    )
    _env(monkeypatch, MISP_CA_BUNDLE=str(pem))
    client = build_misp_client_from_env()
    assert client.http_client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"


def test_missing_ca_bundle_fails_closed(monkeypatch, tmp_path):
    _env(monkeypatch, MISP_CA_BUNDLE=str(tmp_path / "nope.pem"))
    with pytest.raises(RuntimeError, match="MISP_CA_BUNDLE"):
        build_misp_client_from_env()


def test_verify_tls_false_requires_explicit_opt_out(monkeypatch):
    _env(monkeypatch, MISP_VERIFY_TLS="false")
    client = build_misp_client_from_env()
    assert client.http_client._transport._pool._ssl_context.verify_mode.name == "CERT_NONE"


def test_invalid_verify_value_fails_closed(monkeypatch):
    _env(monkeypatch, MISP_VERIFY_TLS="maybe")
    with pytest.raises(RuntimeError, match="MISP_VERIFY_TLS"):
        build_misp_client_from_env()
