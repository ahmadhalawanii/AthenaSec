
"""Wazuh Indexer configuration must always fail closed."""
from pathlib import Path

import pytest

from app.tools.evidence_provider import create_evidence_provider


def configure(monkeypatch):
    monkeypatch.setenv("ATHENASEC_EVIDENCE_PROVIDER", "wazuh")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "athenasec-reader")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "dummy-test-only")
    monkeypatch.delenv("WAZUH_VERIFY_SSL", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_CA_BUNDLE", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT", raising=False)


def test_wazuh_provider_rejects_disabled_tls_verification(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")
    with pytest.raises((ValueError, RuntimeError), match="TLS|SSL|verif"):
        create_evidence_provider()


def test_wazuh_provider_rejects_insecure_url(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "http://wazuh.indexer:9200")
    with pytest.raises((ValueError, RuntimeError), match="HTTPS|https"):
        create_evidence_provider()


def test_wazuh_provider_rejects_admin_user(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "admin")
    with pytest.raises((ValueError, RuntimeError), match="administrator|admin|privilege"):
        create_evidence_provider()


def test_wazuh_provider_accepts_ca_bundle_path(monkeypatch, tmp_path):
    configure(monkeypatch)
    ca = tmp_path / "lab-ca.pem"
    ca.write_text("placeholder certificate for config test", encoding="ascii")
    monkeypatch.setenv("WAZUH_INDEXER_CA_BUNDLE", str(ca))
    gather = create_evidence_provider()
    assert callable(gather)
    assert gather.__self__.client.verify_ssl == str(ca)


def test_wazuh_provider_rejects_missing_ca_path(monkeypatch, tmp_path):
    configure(monkeypatch)
    monkeypatch.setenv("WAZUH_INDEXER_CA_BUNDLE", str(tmp_path / "missing.pem"))
    with pytest.raises((ValueError, RuntimeError), match="CA bundle|certificate"):
        create_evidence_provider()


def test_wazuh_provider_legacy_mode_requires_explicit_ca(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT", "true")
    with pytest.raises((ValueError, RuntimeError), match="CA bundle|certificate"):
        create_evidence_provider()


def test_legacy_context_still_verifies_ca_and_hostname(monkeypatch):
    import certifi
    import ssl
    from app.tools.wazuh_indexer import WazuhIndexerClient
    client = WazuhIndexerClient(
        "https://wazuh.indexer:9200", "reader", "dummy",
        verify_ssl=certifi.where(), legacy_ca_compat=True,
    )
    assert client._legacy_tls_context is not None
    assert client._legacy_tls_context.check_hostname is True
    assert client._legacy_tls_context.verify_mode == ssl.CERT_REQUIRED
    assert not (
        client._legacy_tls_context.verify_flags & ssl.VERIFY_X509_STRICT
    )
