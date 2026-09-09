from __future__ import annotations

import json

from collections.abc import Callable

from training.wazuh_lab_capture import (
    wazuh_replay_remaining_cooldown_seconds,
)


def wait_for_wazuh_rule_cooldown(
    *,
    rule_id: str,
    last_fired_at: float | None,
    now: float,
    sleep_fn: Callable[[float], None],
) -> float:
    if last_fired_at is None:
        return 0

    elapsed_seconds = (
        now
        - last_fired_at
    )

    remaining_seconds = (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id=rule_id,
            elapsed_seconds=elapsed_seconds,
        )
    )

    if remaining_seconds > 0:
        sleep_fn(
            remaining_seconds
        )

    return remaining_seconds

def execute_prepared_behavior_replay(
    *,
    run: dict,
    last_fired_at: float | None,
    now: float,
    sleep_fn: Callable[[float], None],
    command_runner: Callable[[str], object],
) -> float:
    waited = wait_for_wazuh_rule_cooldown(
        rule_id=str(
            run["expected_rule_id"]
        ),
        last_fired_at=last_fired_at,
        now=now,
        sleep_fn=sleep_fn,
    )

    command_runner(
        str(
            run["injection_command"]
        )
    )

    return waited

def execute_prepared_behavior_replay_batch(
    *,
    runs: list[dict],
    clock_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
    command_runner: Callable[[str], object],
    alert_observer: Callable,
    alert_snapshot_fn: Callable[
        [],
        set[str],
    ] | None = None,
    post_observation_fn: Callable | None = None,
) -> None:
    last_fired_at_by_rule: dict[
        str,
        float,
    ] = {}

    for run in runs:
        rule_id = str(
            run["expected_rule_id"]
        )

        wait_for_wazuh_rule_cooldown(
            rule_id=rule_id,
            last_fired_at=(
                last_fired_at_by_rule.get(
                    rule_id
                )
            ),
            now=clock_fn(),
            sleep_fn=sleep_fn,
        )

        before_alert_ids = None

        if alert_snapshot_fn is not None:
            before_alert_ids = (
                alert_snapshot_fn()
            )

        command_runner(
            str(
                run[
                    "injection_command"
                ]
            )
        )

        if before_alert_ids is None:
            alert_observer(
                run
            )

        else:
            alert_observer(
                run,
                before_alert_ids,
            )

        observed_at = clock_fn()

        last_fired_at_by_rule[
            rule_id
        ] = observed_at

        if post_observation_fn is not None:
            post_observation_fn(
                run,
                before_alert_ids,
            )

def wait_for_wazuh_replay_alert_drain(
    *,
    run: dict,
    before_alert_ids: set[str],
    alerts_loader: Callable[
        [],
        list[dict],
    ],
    sleep_fn: Callable[
        [float],
        None,
    ],
    poll_interval_seconds: float,
    max_attempts: int,
) -> int:
    source_ip = str(
        run["source_ip"]
    )

    for attempt in range(
        max_attempts
    ):
        alerts = alerts_loader()

        matching_new_alert_ids = {
            str(
                alert.get(
                    "id",
                    "",
                )
            )
            for alert in alerts
            if (
                str(
                    alert.get(
                        "id",
                        "",
                    )
                )
                not in before_alert_ids
                and str(
                    alert.get(
                        "data",
                        {},
                    ).get(
                        "srcip",
                        "",
                    )
                )
                == source_ip
            )
        }

        observed_count = len(
            matching_new_alert_ids
        )

        if observed_count >= 10:
            return observed_count

        if attempt < max_attempts - 1:
            sleep_fn(
                poll_interval_seconds
            )

    raise ValueError(
        "Wazuh replay alert drain "
        "did not observe all 10 "
        "expected SSH alerts"
    )

def wait_for_wazuh_behavior_replay_drain(
    *,
    run: dict,
    before_alert_ids: set[str],
    alerts_loader: Callable[
        [],
        list[dict],
    ],
    sleep_fn: Callable[
        [float],
        None,
    ],
    poll_interval_seconds: float,
    max_attempts: int,
) -> int:
    ssh_bruteforce_scenarios = {
        "ssh_invalid_user_bruteforce",
        "ssh_root_password_bruteforce",
        "ssh_root_none_bruteforce",
    }

    scenario_name = str(
        run["scenario_name"]
    )

    if (
        scenario_name
        not in ssh_bruteforce_scenarios
    ):
        return 0

    return wait_for_wazuh_replay_alert_drain(
        run=run,
        before_alert_ids=before_alert_ids,
        alerts_loader=alerts_loader,
        sleep_fn=sleep_fn,
        poll_interval_seconds=(
            poll_interval_seconds
        ),
        max_attempts=max_attempts,
    )



def observe_expected_wazuh_alert(
    *,
    run: dict,
    before_alert_ids: set[str],
    alerts_loader: Callable[
        [],
        list[dict],
    ],
    sleep_fn: Callable[[float], None],
    poll_interval_seconds: float,
    max_attempts: int,
) -> dict:
    from training.wazuh_lab_capture import (
        find_latest_matching_alert,
    )

    for attempt in range(
        max_attempts
    ):
        alerts = alerts_loader()

        new_alerts = [
            alert
            for alert in alerts
            if str(
                alert.get(
                    "id",
                    "",
                )
            )
            not in before_alert_ids
        ]

        try:
            return find_latest_matching_alert(
                alerts=new_alerts,
                rule_id=str(
                    run[
                        "expected_rule_id"
                    ]
                ),
                source_ip=str(
                    run[
                        "source_ip"
                    ]
                ),
            )

        except ValueError:
            if (
                attempt
                < max_attempts - 1
            ):
                sleep_fn(
                    poll_interval_seconds
                )

    raise ValueError(
        "Expected new Wazuh alert "
        "was not observed"
    )

def load_wazuh_alerts_from_docker(
    *,
    container_name: str,
    process_runner: Callable[
        [list[str]],
        object,
    ],
) -> list[dict]:
    result = process_runner(
        [
            "docker",
            "exec",
            container_name,
            "cat",
            (
                "/var/ossec/logs/"
                "alerts/alerts.json"
            ),
        ]
    )

    stdout = str(
        result.stdout
    )

    lines = [
        line
        for line in stdout.splitlines()
        if line.strip()
    ]

    alerts = []

    for index, line in enumerate(
        lines
    ):
        try:
            alerts.append(
                json.loads(line)
            )

        except json.JSONDecodeError:
            is_last_line = (
                index
                == len(lines) - 1
            )

            snapshot_ended_mid_line = (
                not stdout.endswith(
                    "\n"
                )
            )

            if (
                is_last_line
                and snapshot_ended_mid_line
            ):
                break

            raise

    return alerts

def run_powershell_injection_command(
    *,
    command: str,
    process_runner: Callable,
):
    return process_runner(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            command,
        ],
        check=True,
    )