import json

from training.behavior_manifest import (
    BehaviorReplay,
    behavior_replay_variation,
    prepare_behavior_replay_run,
    scenario_names_for_label,
)
from training.wazuh_lab_scenarios import (
    get_scenario_by_name,
)
from training.wazuh_replay_runner import (
    prepare_behavior_replay_manifest_runs,
)


def _replay():
    return BehaviorReplay(
        label="privilege_misuse",
        source_dataset="cmu_cert_r4_2",
        source_row_id="scenario-3:test",
        source_behavior="scenario_3",
        scenario_name="sudo_failed_attempt",
    )


def test_sudo_failed_attempt_is_approved_privilege_scenario():
    scenario = get_scenario_by_name(
        "sudo_failed_attempt"
    )

    assert scenario.expected_rule_id == "5401"
    assert scenario.label == "privilege_misuse"
    assert scenario.repetitions == 1

    assert (
        "sudo_failed_attempt"
        in scenario_names_for_label(
            "privilege_misuse"
        )
    )


def test_sudo_failed_attempt_has_eight_feature_variants():
    replay = _replay()

    variations = [
        behavior_replay_variation(
            replay,
            variant_index=index,
        )
        for index in range(8)
    ]

    observed = {
        (
            variation["failed_attempts"],
            variation["target_user"],
            variation["include_command"],
        )
        for variation in variations
    }

    assert observed == {
        ("1", "root", "true"),
        ("1", "root", "false"),
        ("1", "backupuser", "true"),
        ("1", "backupuser", "false"),
        ("2", "root", "true"),
        ("2", "root", "false"),
        ("2", "backupuser", "true"),
        ("2", "backupuser", "false"),
    }


def test_sudo_failed_attempt_variation_changes_real_log():
    replay = _replay()

    runs = [
        prepare_behavior_replay_run(
            replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
            variant_index=index,
        )
        for index in range(8)
    ]

    commands = {
        run["injection_command"]
        for run in runs
    }

    assert len(commands) == 8

    assert any(
        "1 incorrect password attempt"
        in command
        for command in commands
    )

    assert any(
        "2 incorrect password attempts"
        in command
        for command in commands
    )

    assert any(
        "USER=root"
        in command
        for command in commands
    )

    assert any(
        "USER=backupuser"
        in command
        for command in commands
    )

    assert any(
        "COMMAND=/bin/bash"
        in command
        for command in commands
    )

    assert any(
        "COMMAND=/bin/bash"
        not in command
        for command in commands
    )


def test_manifest_runner_expands_sudo_failed_attempt_to_eight_runs(
    tmp_path,
):
    manifest = (
        tmp_path
        / "manifest.jsonl"
    )

    manifest.write_text(
        json.dumps(
            {
                "label": (
                    "privilege_misuse"
                ),
                "source_dataset": (
                    "cmu_cert_r4_2"
                ),
                "source_row_id": (
                    "scenario-3:test"
                ),
                "source_behavior": (
                    "scenario_3"
                ),
                "scenario_name": (
                    "sudo_failed_attempt"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    runs = (
        prepare_behavior_replay_manifest_runs(
            manifest_path=manifest,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    assert len(runs) == 8

    assert {
        run["variant_index"]
        for run in runs
    } == set(
        range(8)
    )

    assert {
        run["expected_rule_id"]
        for run in runs
    } == {
        "5401"
    }
