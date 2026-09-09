from training.wazuh_replay_runner import (
    wait_for_wazuh_rule_cooldown,
)


def test_wait_for_wazuh_rule_cooldown_waits_only_remaining_time():
    slept = []

    waited = wait_for_wazuh_rule_cooldown(
        rule_id="5712",
        last_fired_at=100.0,
        now=125.0,
        sleep_fn=slept.append,
    )

    assert waited == 35
    assert slept == [35]


def test_wait_for_wazuh_rule_cooldown_does_not_wait_when_expired():
    slept = []

    waited = wait_for_wazuh_rule_cooldown(
        rule_id="5763",
        last_fired_at=100.0,
        now=165.0,
        sleep_fn=slept.append,
    )

    assert waited == 0
    assert slept == []


def test_wait_for_wazuh_rule_cooldown_does_not_wait_for_rule_without_ignore():
    slept = []

    waited = wait_for_wazuh_rule_cooldown(
        rule_id="5720",
        last_fired_at=100.0,
        now=100.0,
        sleep_fn=slept.append,
    )

    assert waited == 0
    assert slept == []


def test_wait_for_wazuh_rule_cooldown_does_not_wait_without_previous_fire():
    slept = []

    waited = wait_for_wazuh_rule_cooldown(
        rule_id="5712",
        last_fired_at=None,
        now=100.0,
        sleep_fn=slept.append,
    )

    assert waited == 0
    assert slept == []

def test_execute_prepared_behavior_replay_waits_before_injection():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay,
    )

    actions = []

    run = {
        "expected_rule_id": "5712",
        "injection_command": "inject-test-command",
    }

    waited = execute_prepared_behavior_replay(
        run=run,
        last_fired_at=100.0,
        now=125.0,
        sleep_fn=lambda seconds: actions.append(
            ("sleep", seconds)
        ),
        command_runner=lambda command: actions.append(
            ("execute", command)
        ),
    )

    assert waited == 35

    assert actions == [
        ("sleep", 35),
        (
            "execute",
            "inject-test-command",
        ),
    ]

def test_execute_prepared_behavior_replay_batch_tracks_cooldown_per_rule():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay_batch,
    )

    runs = [
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.10",
            "injection_command": "inject-5712-first",
        },
        {
            "expected_rule_id": "5720",
            "source_ip": "198.18.1.20",
            "injection_command": "inject-5720",
        },
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.30",
            "injection_command": "inject-5712-second",
        },
    ]

    actions = []

    current_time = [100.0]

    def clock_fn():
        return current_time[0]

    def sleep_fn(seconds):
        actions.append(
            ("sleep", seconds)
        )
        current_time[0] += seconds

    def command_runner(command):
        actions.append(
            ("execute", command)
        )
        current_time[0] += 10

    def alert_observer(run):
        actions.append(
            (
                "observe",
                run["expected_rule_id"],
                run["source_ip"],
            )
        )

        current_time[0] += 2

        return current_time[0]

    execute_prepared_behavior_replay_batch(
        runs=runs,
        clock_fn=clock_fn,
        sleep_fn=sleep_fn,
        command_runner=command_runner,
        alert_observer=alert_observer,
    )

    runs = [
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.10",
            "injection_command": "inject-5712-first",
        },
        {
            "expected_rule_id": "5720",
            "source_ip": "198.18.1.20",
            "injection_command": "inject-5720",
        },
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.30",
            "injection_command": "inject-5712-second",
        },
    ]


    assert actions == [
        (
            "execute",
            "inject-5712-first",
        ),
        (
            "observe",
            "5712",
            "198.18.1.10",
        ),
        (
            "execute",
            "inject-5720",
        ),
        (
            "observe",
            "5720",
            "198.18.1.20",
        ),
        (
            "sleep",
            48,
        ),
        (
            "execute",
            "inject-5712-second",
        ),
        (
            "observe",
            "5712",
            "198.18.1.30",
        ),
    ]

def test_execute_prepared_behavior_replay_batch_snapshots_alerts_before_injection():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay_batch,
    )

    runs = [
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.10",
            "injection_command": "inject-5712",
        },
    ]

    actions = []

    current_time = [100.0]

    def clock_fn():
        return current_time[0]

    def sleep_fn(seconds):
        actions.append(
            ("sleep", seconds)
        )
        current_time[0] += seconds

    def alert_snapshot_fn():
        actions.append(
            ("snapshot",)
        )

        return {
            "old-alert-1",
            "old-alert-2",
        }

    def command_runner(command):
        actions.append(
            ("execute", command)
        )
        current_time[0] += 10

    def alert_observer(
        run,
        before_alert_ids,
    ):
        actions.append(
            (
                "observe",
                run["expected_rule_id"],
                run["source_ip"],
                before_alert_ids,
            )
        )

        current_time[0] += 2

        return current_time[0]

    execute_prepared_behavior_replay_batch(
        runs=runs,
        clock_fn=clock_fn,
        sleep_fn=sleep_fn,
        command_runner=command_runner,
        alert_snapshot_fn=alert_snapshot_fn,
        alert_observer=alert_observer,
    )

    assert actions == [
        (
            "snapshot",
        ),
        (
            "execute",
            "inject-5712",
        ),
        (
            "observe",
            "5712",
            "198.18.1.10",
            {
                "old-alert-1",
                "old-alert-2",
            },
        ),
    ]

def test_observe_expected_wazuh_alert_ignores_old_alert_and_returns_new_match():
    from training.wazuh_replay_runner import (
        observe_expected_wazuh_alert,
    )

    run = {
        "expected_rule_id": "5763",
        "source_ip": "198.18.10.20",
    }

    old_matching_alert = {
        "id": "old-match",
        "rule": {
            "id": "5763",
        },
        "data": {
            "srcip": "198.18.10.20",
        },
    }

    unrelated_new_alert = {
        "id": "new-unrelated",
        "rule": {
            "id": "5760",
        },
        "data": {
            "srcip": "198.18.10.20",
        },
    }

    new_matching_alert = {
        "id": "new-match",
        "rule": {
            "id": "5763",
        },
        "data": {
            "srcip": "198.18.10.20",
        },
    }

    alert_reads = [
        [
            old_matching_alert,
            unrelated_new_alert,
        ],
        [
            old_matching_alert,
            unrelated_new_alert,
            new_matching_alert,
        ],
    ]

    sleeps = []

    def alerts_loader():
        return alert_reads.pop(0)

    event = observe_expected_wazuh_alert(
        run=run,
        before_alert_ids={
            "old-match",
        },
        alerts_loader=alerts_loader,
        sleep_fn=sleeps.append,
        poll_interval_seconds=0.5,
        max_attempts=2,
    )

    assert event == new_matching_alert

    assert sleeps == [
        0.5,
    ]


def test_load_wazuh_alerts_from_docker_parses_json_lines():
    from training.wazuh_replay_runner import (
        load_wazuh_alerts_from_docker,
    )

    calls = []

    class Result:
        stdout = (
            '{"id":"alert-1","rule":{"id":"5712"}}\n'
            '{"id":"alert-2","rule":{"id":"5763"}}\n'
        )

    def process_runner(command):
        calls.append(command)

        return Result()

    alerts = load_wazuh_alerts_from_docker(
        container_name="single-node-wazuh.manager-1",
        process_runner=process_runner,
    )

    assert alerts == [
        {
            "id": "alert-1",
            "rule": {
                "id": "5712",
            },
        },
        {
            "id": "alert-2",
            "rule": {
                "id": "5763",
            },
        },
    ]

    assert calls == [
        [
            "docker",
            "exec",
            "single-node-wazuh.manager-1",
            "cat",
            "/var/ossec/logs/alerts/alerts.json",
        ],
    ]

def test_run_powershell_injection_command_executes_exact_command():
    from training.wazuh_replay_runner import (
        run_powershell_injection_command,
    )

    calls = []

    class Result:
        returncode = 0

    def process_runner(
        command,
        **kwargs,
    ):
        calls.append(
            (
                command,
                kwargs,
            )
        )

        return Result()

    result = run_powershell_injection_command(
        command="inject-test-command",
        process_runner=process_runner,
    )

    assert result.returncode == 0

    assert calls == [
        (
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "inject-test-command",
            ],
            {
                "check": True,
            },
        ),
    ]

def test_execute_prepared_behavior_replay_batch_records_observed_alert_time():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay_batch,
    )

    runs = [
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.10",
            "injection_command": "inject-first",
        },
        {
            "expected_rule_id": "5712",
            "source_ip": "198.18.1.20",
            "injection_command": "inject-second",
        },
    ]

    actions = []

    current_time = [100.0]

    def clock_fn():
        return current_time[0]

    def sleep_fn(seconds):
        actions.append(
            ("sleep", seconds)
        )
        current_time[0] += seconds

    def command_runner(command):
        actions.append(
            ("execute", command)
        )
        current_time[0] += 10

    def alert_snapshot_fn():
        return set()

    def alert_observer(
        run,
        before_alert_ids,
    ):
        actions.append(
            (
                "observe",
                run["source_ip"],
            )
        )

        current_time[0] += 2

        return {
            "id": (
                "alert-"
                + run["source_ip"]
            ),
            "rule": {
                "id": run[
                    "expected_rule_id"
                ],
            },
            "data": {
                "srcip": run[
                    "source_ip"
                ],
            },
        }

    execute_prepared_behavior_replay_batch(
        runs=runs,
        clock_fn=clock_fn,
        sleep_fn=sleep_fn,
        command_runner=command_runner,
        alert_snapshot_fn=alert_snapshot_fn,
        alert_observer=alert_observer,
    )

    assert actions == [
        (
            "execute",
            "inject-first",
        ),
        (
            "observe",
            "198.18.1.10",
        ),
        (
            "sleep",
            60,
        ),
        (
            "execute",
            "inject-second",
        ),
        (
            "observe",
            "198.18.1.20",
        ),
    ]

def test_load_wazuh_alerts_from_docker_ignores_incomplete_trailing_line():
    from training.wazuh_replay_runner import (
        load_wazuh_alerts_from_docker,
    )

    class Result:
        stdout = (
            '{"id":"alert-1","rule":{"id":"5760"}}\n'
            '{"id":"alert-2","rule":{"id":"5763"}}\n'
            '{"id":"partial","rule":{"description":"unfinished'
        )

    def process_runner(command):
        return Result()

    alerts = load_wazuh_alerts_from_docker(
        container_name="single-node-wazuh.manager-1",
        process_runner=process_runner,
    )

    assert alerts == [
        {
            "id": "alert-1",
            "rule": {
                "id": "5760",
            },
        },
        {
            "id": "alert-2",
            "rule": {
                "id": "5763",
            },
        },
    ]

def test_execute_prepared_behavior_replay_batch_drains_before_next_injection():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay_batch,
    )

    events = []

    runs = [
        {
            "scenario_name": (
                "ssh_root_none_bruteforce"
            ),
            "expected_rule_id": "5720",
            "source_ip": "198.19.1.1",
            "injection_command": "inject-first",
        },
        {
            "scenario_name": (
                "ssh_root_none_bruteforce"
            ),
            "expected_rule_id": "5720",
            "source_ip": "198.19.1.2",
            "injection_command": "inject-second",
        },
    ]

    def command_runner(command):
        events.append(
            f"inject:{command}"
        )

    def alert_snapshot_fn():
        return set()

    def alert_observer(
        run,
        before_alert_ids,
    ):
        events.append(
            "observe:"
            + run["source_ip"]
        )

        return {
            "id": (
                "alert-"
                + run["source_ip"]
            )
        }

    def post_observation_fn(
        run,
        before_alert_ids,
    ):
        events.append(
            "drain:"
            + run["source_ip"]
        )

    execute_prepared_behavior_replay_batch(
        runs=runs,
        clock_fn=lambda: 100.0,
        sleep_fn=lambda seconds: None,
        command_runner=command_runner,
        alert_snapshot_fn=alert_snapshot_fn,
        alert_observer=alert_observer,
        post_observation_fn=(
            post_observation_fn
        ),
    )

    assert events == [
        "inject:inject-first",
        "observe:198.19.1.1",
        "drain:198.19.1.1",
        "inject:inject-second",
        "observe:198.19.1.2",
        "drain:198.19.1.2",
    ]

def test_wait_for_wazuh_replay_alert_drain_waits_for_all_ten_ssh_alerts():
    from training.wazuh_replay_runner import (
        wait_for_wazuh_replay_alert_drain,
    )

    run = {
        "scenario_name": (
            "ssh_root_none_bruteforce"
        ),
        "expected_rule_id": "5720",
        "source_ip": "198.19.47.171",
    }

    before_alert_ids = {
        "old-alert",
    }

    first_poll = []

    for index in range(7):
        first_poll.append(
            {
                "id": f"new-5716-{index}",
                "rule": {
                    "id": "5716",
                },
                "data": {
                    "srcip": "198.19.47.171",
                },
            }
        )

    first_poll.append(
        {
            "id": "new-5720",
            "rule": {
                "id": "5720",
            },
            "data": {
                "srcip": "198.19.47.171",
            },
        }
    )

    second_poll = (
        first_poll
        + [
            {
                "id": "new-5716-8",
                "rule": {
                    "id": "5716",
                },
                "data": {
                    "srcip": "198.19.47.171",
                },
            },
            {
                "id": "new-5716-9",
                "rule": {
                    "id": "5716",
                },
                "data": {
                    "srcip": "198.19.47.171",
                },
            },
        ]
    )

    polls = [
        [
            {
                "id": "old-alert",
                "rule": {
                    "id": "5716",
                },
                "data": {
                    "srcip": "198.19.47.171",
                },
            },
            *first_poll,
            {
                "id": "unrelated",
                "rule": {
                    "id": "5716",
                },
                "data": {
                    "srcip": "198.19.99.99",
                },
            },
        ],
        second_poll,
    ]

    sleeps = []

    def alerts_loader():
        return polls.pop(0)

    def sleep_fn(seconds):
        sleeps.append(
            seconds
        )

    observed_count = (
        wait_for_wazuh_replay_alert_drain(
            run=run,
            before_alert_ids=before_alert_ids,
            alerts_loader=alerts_loader,
            sleep_fn=sleep_fn,
            poll_interval_seconds=0.5,
            max_attempts=5,
        )
    )

    assert observed_count == 10

    assert sleeps == [
        0.5,
    ]

def test_wait_for_wazuh_behavior_replay_drain_only_drains_ssh_bruteforce():
    from training.wazuh_replay_runner import (
        wait_for_wazuh_behavior_replay_drain,
    )

    ssh_run = {
        "scenario_name": (
            "ssh_invalid_user_bruteforce"
        ),
        "expected_rule_id": "5712",
        "source_ip": "198.19.10.10",
    }

    benign_run = {
        "scenario_name": (
            "ssh_authentication_success"
        ),
        "expected_rule_id": "5715",
        "source_ip": "198.19.20.20",
    }

    ssh_alerts = [
        {
            "id": f"ssh-{index}",
            "rule": {
                "id": "5710",
            },
            "data": {
                "srcip": "198.19.10.10",
            },
        }
        for index in range(10)
    ]

    loader_calls = []

    def alerts_loader():
        loader_calls.append(
            "called"
        )

        return ssh_alerts

    ssh_count = (
        wait_for_wazuh_behavior_replay_drain(
            run=ssh_run,
            before_alert_ids=set(),
            alerts_loader=alerts_loader,
            sleep_fn=lambda seconds: None,
            poll_interval_seconds=0.5,
            max_attempts=5,
        )
    )

    assert ssh_count == 10

    calls_after_ssh = len(
        loader_calls
    )

    benign_count = (
        wait_for_wazuh_behavior_replay_drain(
            run=benign_run,
            before_alert_ids=set(),
            alerts_loader=alerts_loader,
            sleep_fn=lambda seconds: None,
            poll_interval_seconds=0.5,
            max_attempts=5,
        )
    )

    assert benign_count == 0

    assert (
        len(loader_calls)
        == calls_after_ssh
    )

def test_prepare_behavior_replay_manifest_runs_reads_jsonl(
    tmp_path,
):
    import json

    from training import wazuh_replay_runner

    manifest_path = (
        tmp_path
        / "behavior_replay_manifest.jsonl"
    )

    records = [
        {
            "label": "benign",
            "source_dataset": "cic_ids_2018",
            "source_row_id": "sample.csv:1",
            "source_behavior": "Benign",
            "scenario_name": (
                "ssh_authentication_success"
            ),
        },
        {
            "label": "privilege_misuse",
            "source_dataset": "adfa_ld",
            "source_row_id": (
                "Attack_Data_Master/"
                "Adduser_1/trace.txt"
            ),
            "source_behavior": "Adduser_1",
            "scenario_name": (
                "user_added_to_sudo_group"
            ),
        },
    ]

    manifest_path.write_text(
        "\n".join(
            json.dumps(record)
            for record in records
        )
        + "\n",
        encoding="utf-8",
    )

    runs = (
        wazuh_replay_runner
        .prepare_behavior_replay_manifest_runs(
            manifest_path=manifest_path,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    assert len(runs) == 2

    assert runs[0]["label"] == "benign"
    assert (
        runs[0]["source_dataset"]
        == "cic_ids_2018"
    )
    assert (
        runs[0]["scenario_name"]
        == "ssh_authentication_success"
    )

    assert (
        runs[1]["label"]
        == "privilege_misuse"
    )
    assert (
        runs[1]["source_dataset"]
        == "adfa_ld"
    )
    assert (
        runs[1]["scenario_name"]
        == "user_added_to_sudo_group"
    )

def test_behavior_replay_capture_record_preserves_run_provenance():
    from training import wazuh_replay_runner

    run = {
        "label": "brute_force",
        "source_dataset": "cic_ids_2017",
        "source_row_id": "Tuesday.csv:100",
        "source_behavior": "SSH-Patator",
        "scenario_name": (
            "ssh_root_password_bruteforce"
        ),
        "wazuh_source_dataset": "wazuh_lab",
        "wazuh_source_row_id": (
            "ssh_root_password_bruteforce_001"
        ),
    }

    event = {
        "id": "wazuh-alert-1",
        "rule": {
            "id": "5763",
            "level": 10,
        },
        "data": {
            "srcip": "198.18.20.30",
        },
    }

    record = (
        wazuh_replay_runner
        .behavior_replay_capture_record(
            run=run,
            event=event,
        )
    )

    assert record == {
        "event": event,
        "label": "brute_force",
        "source_dataset": "cic_ids_2017",
        "source_row_id": "Tuesday.csv:100",
        "source_behavior": "SSH-Patator",
        "scenario_name": (
            "ssh_root_password_bruteforce"
        ),
        "wazuh_source_dataset": "wazuh_lab",
        "wazuh_source_row_id": (
            "ssh_root_password_bruteforce_001"
        ),
    }

def test_append_behavior_replay_capture_writes_jsonl(
    tmp_path,
):
    import json

    from training import wazuh_replay_runner

    output_path = (
        tmp_path
        / "replay_captures.jsonl"
    )

    first = {
        "event": {
            "id": "alert-1",
        },
        "label": "benign",
    }

    second = {
        "event": {
            "id": "alert-2",
        },
        "label": "brute_force",
    }

    wazuh_replay_runner.append_behavior_replay_capture(
        output_path=output_path,
        record=first,
    )

    wazuh_replay_runner.append_behavior_replay_capture(
        output_path=output_path,
        record=second,
    )

    written = [
        json.loads(line)
        for line in output_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert written == [
        first,
        second,
    ]

def test_execute_prepared_behavior_replay_batch_returns_observed_events():
    from training.wazuh_replay_runner import (
        execute_prepared_behavior_replay_batch,
    )

    run = {
        "expected_rule_id": "5715",
        "source_ip": "198.18.1.10",
        "injection_command": "inject-test",
    }

    observed_event = {
        "id": "alert-1",
        "rule": {
            "id": "5715",
        },
        "data": {
            "srcip": "198.18.1.10",
        },
    }

    events = (
        execute_prepared_behavior_replay_batch(
            runs=[run],
            clock_fn=lambda: 100.0,
            sleep_fn=lambda seconds: None,
            command_runner=lambda command: None,
            alert_snapshot_fn=lambda: set(),
            alert_observer=(
                lambda run, before_alert_ids:
                observed_event
            ),
        )
    )

    assert events == [
        observed_event,
    ]

def test_execute_behavior_replay_manifest_writes_capture_records(
    tmp_path,
):
    import json

    from training import wazuh_replay_runner

    manifest_path = (
        tmp_path
        / "behavior_replay_manifest.jsonl"
    )

    output_path = (
        tmp_path
        / "replay_captures.jsonl"
    )

    manifest_record = {
        "label": "benign",
        "source_dataset": "cic_ids_2018",
        "source_row_id": "sample.csv:1",
        "source_behavior": "Benign",
        "scenario_name": (
            "ssh_authentication_success"
        ),
    }

    manifest_path.write_text(
        json.dumps(manifest_record)
        + "\n",
        encoding="utf-8",
    )

    executed_commands = []

    observed_event = {
        "id": "new-alert-1",
        "rule": {
            "id": "5715",
            "level": 3,
        },
        "data": {},
    }

    records = (
        wazuh_replay_runner
        .execute_behavior_replay_manifest(
            manifest_path=manifest_path,
            output_path=output_path,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
            clock_fn=lambda: 100.0,
            sleep_fn=lambda seconds: None,
            command_runner=(
                executed_commands.append
            ),
            alert_snapshot_fn=lambda: set(),
            alert_observer=(
                lambda run, before_alert_ids:
                observed_event
            ),
        )
    )

    assert len(records) == 1

    assert records[0]["event"] == (
        observed_event
    )

    assert (
        records[0]["label"]
        == "benign"
    )

    assert (
        records[0]["source_dataset"]
        == "cic_ids_2018"
    )

    assert (
        records[0]["source_row_id"]
        == "sample.csv:1"
    )

    assert (
        records[0]["source_behavior"]
        == "Benign"
    )

    assert (
        records[0]["scenario_name"]
        == "ssh_authentication_success"
    )

    written = [
        json.loads(line)
        for line in output_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert written == records

    assert len(executed_commands) == 1