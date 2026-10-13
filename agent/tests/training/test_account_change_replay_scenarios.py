from training.behavior_manifest import (
    scenario_names_for_label,
)
from training.wazuh_lab_scenarios import (
    get_scenario_by_name,
)


def test_normal_account_created_is_approved_benign():
    scenario = get_scenario_by_name(
        "normal_account_created"
    )

    assert scenario.label == "benign"
    assert scenario.expected_rule_id == "5902"
    assert (
        "name=testuser"
        in scenario.log_line
    )

    assert (
        "normal_account_created"
        in scenario_names_for_label(
            "benign"
        )
    )


def test_privileged_account_created_is_approved_privilege_misuse():
    scenario = get_scenario_by_name(
        "privileged_account_created"
    )

    assert (
        scenario.label
        == "privilege_misuse"
    )

    assert (
        scenario.expected_rule_id
        == "5902"
    )

    assert (
        "name=admin"
        in scenario.log_line
    )

    assert (
        "privileged_account_created"
        in scenario_names_for_label(
            "privilege_misuse"
        )
    )


def test_normal_group_created_is_approved_benign():
    scenario = get_scenario_by_name(
        "normal_group_created"
    )

    assert scenario.label == "benign"
    assert scenario.expected_rule_id == "5901"

    assert (
        "name=developers"
        in scenario.log_line
    )

    assert (
        "normal_group_created"
        in scenario_names_for_label(
            "benign"
        )
    )


def test_privileged_group_created_is_approved_privilege_misuse():
    scenario = get_scenario_by_name(
        "privileged_group_created"
    )

    assert (
        scenario.label
        == "privilege_misuse"
    )

    assert (
        scenario.expected_rule_id
        == "5901"
    )

    assert (
        "name=wheel"
        in scenario.log_line
    )

    assert (
        "privileged_group_created"
        in scenario_names_for_label(
            "privilege_misuse"
        )
    )


def test_account_change_pairs_use_same_rules_but_different_semantics():
    normal_account = (
        get_scenario_by_name(
            "normal_account_created"
        )
    )

    privileged_account = (
        get_scenario_by_name(
            "privileged_account_created"
        )
    )

    normal_group = (
        get_scenario_by_name(
            "normal_group_created"
        )
    )

    privileged_group = (
        get_scenario_by_name(
            "privileged_group_created"
        )
    )

    assert (
        normal_account.expected_rule_id
        == privileged_account.expected_rule_id
        == "5902"
    )

    assert (
        normal_group.expected_rule_id
        == privileged_group.expected_rule_id
        == "5901"
    )

    assert (
        normal_account.log_line
        != privileged_account.log_line
    )

    assert (
        normal_group.log_line
        != privileged_group.log_line
    )
