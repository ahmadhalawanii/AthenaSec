import pytest

from training.wazuh_lab_scenarios import (
    WazuhLabScenario,
    benign_scenarios,
    brute_force_scenarios,
    docker_injection_command,
    get_scenario_by_name,
    prepare_scenario_run,
    privilege_misuse_scenarios,
)


def test_brute_force_scenarios_include_known_wazuh_paths():
    scenarios = brute_force_scenarios()

    names = {
        scenario.name
        for scenario in scenarios
    }

    assert "ssh_invalid_user_bruteforce" in names
    assert "ssh_root_password_bruteforce" in names
    assert "ssh_root_none_bruteforce" in names


def test_brute_force_scenarios_have_expected_rule_ids():
    scenarios = {
        scenario.name: scenario
        for scenario in brute_force_scenarios()
    }

    assert (
        scenarios[
            "ssh_invalid_user_bruteforce"
        ].expected_rule_id
        == "5712"
    )

    assert (
        scenarios[
            "ssh_root_password_bruteforce"
        ].expected_rule_id
        == "5763"
    )

    assert (
        scenarios[
            "ssh_root_none_bruteforce"
        ].expected_rule_id
        == "5720"
    )


def test_wazuh_lab_scenario_preserves_label_and_provenance():
    scenario = WazuhLabScenario(
        name="sample",
        log_line=(
            "Sep  3 01:00:00 testhost "
            "sshd[12345]: Failed none for root "
            "from 192.0.2.10 port 50000 ssh2"
        ),
        expected_rule_id="5720",
        source_ip="192.0.2.10",
        label="brute_force",
        source_dataset="wazuh_lab",
        source_row_id="sample-001",
        repetitions=10,
    )

    assert scenario.label == "brute_force"
    assert scenario.source_dataset == "wazuh_lab"
    assert scenario.source_row_id == "sample-001"
    assert scenario.repetitions == 10


def test_docker_injection_command_uses_scenario_log_and_repetitions():
    scenario = WazuhLabScenario(
        name="sample",
        log_line=(
            "Sep  3 01:00:00 testhost "
            "sshd[12345]: Failed none for root "
            "from 192.0.2.10 port 50000 ssh2"
        ),
        expected_rule_id="5720",
        source_ip="192.0.2.10",
        label="brute_force",
        source_dataset="wazuh_lab",
        source_row_id="sample-001",
        repetitions=10,
    )

    command = docker_injection_command(
        scenario=scenario,
        container_name="single-node-wazuh.manager-1",
        log_path="/var/ossec/logs/athenasec-test.log",
    )

    assert "1..10" in command
    assert "single-node-wazuh.manager-1" in command
    assert "/var/ossec/logs/athenasec-test.log" in command
    assert scenario.log_line in command


def test_get_scenario_by_name_returns_matching_scenario():
    scenario = get_scenario_by_name(
        "ssh_root_password_bruteforce"
    )

    assert scenario.name == (
        "ssh_root_password_bruteforce"
    )

    assert scenario.expected_rule_id == "5763"


def test_get_scenario_by_name_rejects_unknown_name():
    with pytest.raises(
        ValueError,
        match="Unknown Wazuh lab scenario",
    ):
        get_scenario_by_name(
            "does_not_exist"
        )

def test_prepare_scenario_run_returns_expected_execution_data():
    run = prepare_scenario_run(
        name="ssh_root_password_bruteforce",
        container_name="single-node-wazuh.manager-1",
        log_path="/var/ossec/logs/athenasec-test.log",
    )

    assert run["scenario_name"] == (
        "ssh_root_password_bruteforce"
    )
    assert run["expected_rule_id"] == "5763"
    assert run["source_ip"] == "198.51.100.25"
    assert run["label"] == "brute_force"
    assert run["source_dataset"] == "wazuh_lab"
    assert run["source_row_id"] == (
        "ssh_root_password_bruteforce_002"
    )
    assert "docker exec" in run["injection_command"]


def test_prepare_scenario_run_rejects_unknown_scenario():
    with pytest.raises(
        ValueError,
        match="Unknown Wazuh lab scenario",
    ):
        prepare_scenario_run(
            name="does_not_exist",
            container_name="single-node-wazuh.manager-1",
            log_path="/var/ossec/logs/athenasec-test.log",
        )


def test_privilege_misuse_scenarios_include_known_wazuh_paths():
    scenarios = privilege_misuse_scenarios()

    names = {
        scenario.name
        for scenario in scenarios
    }

    assert "sudo_three_failed_attempts" in names
    assert "sudo_unauthorized_user" in names
    assert "sudo_command_not_allowed" in names
    assert "user_added_to_sudo_group" in names


def test_privilege_misuse_scenarios_have_expected_rule_ids():
    scenarios = {
        scenario.name: scenario
        for scenario in privilege_misuse_scenarios()
    }

    assert (
        scenarios[
            "sudo_three_failed_attempts"
        ].expected_rule_id
        == "5404"
    )

    assert (
        scenarios[
            "sudo_unauthorized_user"
        ].expected_rule_id
        == "5405"
    )

    assert (
        scenarios[
            "sudo_command_not_allowed"
        ].expected_rule_id
        == "5406"
    )

    assert (
        scenarios[
            "user_added_to_sudo_group"
        ].expected_rule_id
        == "2961"
    )


def test_privilege_misuse_scenarios_use_privilege_label():
    scenarios = privilege_misuse_scenarios()

    assert all(
        scenario.label == "privilege_misuse"
        for scenario in scenarios
    )


def test_privilege_misuse_scenarios_use_single_injection():
    scenarios = {
        scenario.name: scenario
        for scenario in privilege_misuse_scenarios()
    }

    assert (
        scenarios[
            "sudo_three_failed_attempts"
        ].repetitions
        == 1
    )

    assert (
        scenarios[
            "sudo_unauthorized_user"
        ].repetitions
        == 1
    )

    assert (
        scenarios[
            "sudo_command_not_allowed"
        ].repetitions
        == 1
    )

    assert (
        scenarios[
            "user_added_to_sudo_group"
        ].repetitions
        == 1
    )

def test_benign_scenarios_include_known_wazuh_paths():
    scenarios = benign_scenarios()

    names = {
        scenario.name
        for scenario in scenarios
    }

    assert "ssh_authentication_success" in names
    assert "sudo_non_privileged_success" in names
    assert "pam_login_session_opened" in names


def test_benign_scenarios_have_expected_rule_ids():
    scenarios = {
        scenario.name: scenario
        for scenario in benign_scenarios()
    }

    assert (
        scenarios[
            "ssh_authentication_success"
        ].expected_rule_id
        == "5715"
    )

    assert (
        scenarios[
            "sudo_non_privileged_success"
        ].expected_rule_id
        == "5407"
    )

    assert (
        scenarios[
            "pam_login_session_opened"
        ].expected_rule_id
        == "5501"
    )


def test_benign_scenarios_use_benign_label():
    assert all(
        scenario.label == "benign"
        for scenario in benign_scenarios()
    )


def test_benign_sudo_repeats_for_fts_transition():
    scenarios = {
        scenario.name: scenario
        for scenario in benign_scenarios()
    }

    assert (
        scenarios[
            "sudo_non_privileged_success"
        ].repetitions
        == 2
    )

def test_privilege_misuse_scenarios_use_clear_sudo_misuse_paths():
    scenarios = {
        scenario.name: scenario
        for scenario in privilege_misuse_scenarios()
    }

    assert "sudo_three_failed_attempts" in scenarios
    assert "sudo_command_not_allowed" in scenarios

    assert (
        scenarios[
            "sudo_three_failed_attempts"
        ].expected_rule_id
        == "5404"
    )

    assert (
        scenarios[
            "sudo_command_not_allowed"
        ].expected_rule_id
        == "5406"
    )


def test_privilege_misuse_scenarios_remove_ambiguous_paths():
    names = {
        scenario.name
        for scenario in privilege_misuse_scenarios()
    }

    assert "sudo_root_success" not in names
    assert "new_user_created" not in names