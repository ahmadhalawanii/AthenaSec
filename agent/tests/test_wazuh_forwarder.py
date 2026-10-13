import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "integrations"
    / "custom-athenasec.py"
)


def load_forwarder_module():
    spec = importlib.util.spec_from_file_location(
        "custom_athenasec",
        SCRIPT_PATH,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    return module


def test_load_alert_reads_wazuh_json(
    tmp_path,
):
    module = load_forwarder_module()

    alert_file = (
        tmp_path
        / "alert.json"
    )

    alert_file.write_text(
        json.dumps(
            {
                "id": "123",
                "rule": {
                    "id": "5712",
                },
            }
        ),
        encoding="utf-8",
    )

    result = module.load_alert(
        str(alert_file)
    )

    assert result["id"] == "123"

    assert (
        result["rule"]["id"]
        == "5712"
    )


def test_build_request_uses_key_and_json():
    module = load_forwarder_module()

    request = module.build_request(
        {
            "id": "123",
            "rule": {
                "id": "5712",
            },
        },
        api_key="secret-key",
        hook_url=(
            "http://athenasec:8000/"
            "api/v1/integrations/wazuh/alerts"
        ),
    )

    assert request.full_url == (
        "http://athenasec:8000/"
        "api/v1/integrations/wazuh/alerts"
    )

    headers = {
        key.lower(): value
        for key, value
        in request.header_items()
    }

    assert headers[
        "x-athenasec-integration-key"
    ] == "secret-key"

    assert headers[
        "content-type"
    ] == "application/json"

    body = json.loads(
        request.data.decode(
            "utf-8"
        )
    )

    assert body["id"] == "123"


def test_main_uses_wazuh_argument_order(
    tmp_path,
    monkeypatch,
):
    module = load_forwarder_module()

    alert_file = (
        tmp_path
        / "alert.json"
    )

    alert_file.write_text(
        json.dumps(
            {
                "id": "123",
                "rule": {
                    "id": "5712",
                },
            }
        ),
        encoding="utf-8",
    )

    captured = {}

    def fake_send_alert(
        alert,
        api_key,
        hook_url,
    ):
        captured["alert"] = alert
        captured["api_key"] = api_key
        captured["hook_url"] = hook_url

        return {
            "status": "complete"
        }

    monkeypatch.setattr(
        module,
        "send_alert",
        fake_send_alert,
    )

    exit_code = module.main(
        [
            "custom-athenasec.py",
            str(alert_file),
            "secret-key",
            (
                "http://athenasec:8000/"
                "api/v1/integrations/"
                "wazuh/alerts"
            ),
        ]
    )

    assert exit_code == 0

    assert (
        captured["alert"]["id"]
        == "123"
    )

    assert (
        captured["api_key"]
        == "secret-key"
    )

    assert captured[
        "hook_url"
    ] == (
        "http://athenasec:8000/"
        "api/v1/integrations/"
        "wazuh/alerts"
    )


def test_main_rejects_missing_arguments():
    module = load_forwarder_module()

    exit_code = module.main(
        [
            "custom-athenasec.py"
        ]
    )

    assert exit_code == 2