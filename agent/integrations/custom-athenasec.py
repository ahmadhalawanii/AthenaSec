#!/var/ossec/framework/python/bin/python3

import json
import sys
from typing import Any
from urllib.error import (
    HTTPError,
    URLError,
)
from urllib.request import (
    Request,
    urlopen,
)


TIMEOUT_SECONDS = 30

INTEGRATION_HEADER = (
    "X-AthenaSec-Integration-Key"
)


def load_alert(
    alert_file_path: str,
) -> dict[str, Any]:
    with open(
        alert_file_path,
        "r",
        encoding="utf-8",
    ) as alert_file:
        alert = json.load(
            alert_file
        )

    if not isinstance(
        alert,
        dict,
    ):
        raise ValueError(
            "Wazuh alert must be a JSON object."
        )

    return alert


def build_request(
    alert: dict[str, Any],
    api_key: str,
    hook_url: str,
) -> Request:
    body = json.dumps(
        alert
    ).encode(
        "utf-8"
    )

    return Request(
        url=hook_url,
        data=body,
        headers={
            "Content-Type": (
                "application/json"
            ),
            INTEGRATION_HEADER: (
                api_key
            ),
        },
        method="POST",
    )


def send_alert(
    alert: dict[str, Any],
    api_key: str,
    hook_url: str,
) -> dict[str, Any]:
    request = build_request(
        alert,
        api_key,
        hook_url,
    )

    with urlopen(
        request,
        timeout=TIMEOUT_SECONDS,
    ) as response:
        response_body = (
            response
            .read()
            .decode(
                "utf-8"
            )
        )

        status = getattr(
            response,
            "status",
            200,
        )

        if not (
            200
            <= status
            < 300
        ):
            raise RuntimeError(
                "AthenaSec returned "
                f"HTTP {status}."
            )

    if not response_body:
        return {}

    result = json.loads(
        response_body
    )

    if not isinstance(
        result,
        dict,
    ):
        raise ValueError(
            "AthenaSec response "
            "must be a JSON object."
        )

    return result


def main(
    argv: list[str] | None = None,
) -> int:
    arguments = (
        sys.argv
        if argv is None
        else argv
    )

    if len(arguments) < 4:
        print(
            (
                "Usage: custom-athenasec.py "
                "<alert_file> "
                "<api_key> "
                "<hook_url>"
            ),
            file=sys.stderr,
        )

        return 2

    alert_file_path = (
        arguments[1]
    )

    api_key = (
        arguments[2]
    )

    hook_url = (
        arguments[3]
    )

    if not alert_file_path:
        print(
            "Alert file path is missing.",
            file=sys.stderr,
        )

        return 2

    if not api_key:
        print(
            "AthenaSec integration key "
            "is missing.",
            file=sys.stderr,
        )

        return 2

    if not hook_url:
        print(
            "AthenaSec hook URL is missing.",
            file=sys.stderr,
        )

        return 2

    try:
        alert = load_alert(
            alert_file_path
        )

        send_alert(
            alert,
            api_key,
            hook_url,
        )

    except FileNotFoundError as exc:
        print(
            (
                "AthenaSec integration "
                f"alert file error: {exc}"
            ),
            file=sys.stderr,
        )

        return 1

    except json.JSONDecodeError as exc:
        print(
            (
                "AthenaSec integration "
                f"JSON error: {exc}"
            ),
            file=sys.stderr,
        )

        return 1

    except HTTPError as exc:
        print(
            (
                "AthenaSec integration "
                f"HTTP error: {exc.code}"
            ),
            file=sys.stderr,
        )

        return 1

    except URLError as exc:
        print(
            (
                "AthenaSec integration "
                f"connection error: "
                f"{exc.reason}"
            ),
            file=sys.stderr,
        )

        return 1

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        print(
            (
                "AthenaSec integration "
                f"error: {exc}"
            ),
            file=sys.stderr,
        )

        return 1

    except Exception as exc:
        print(
            (
                "AthenaSec integration "
                f"unexpected error: {exc}"
            ),
            file=sys.stderr,
        )

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )