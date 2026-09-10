import dataclasses

import pytest

from training import behavior_manifest
from training.behavior_manifest import (
    BehaviorReplay,
)
from training.wazuh_lab_scenarios import (
    get_scenario_by_name,
)


def test_behavior_replay_preserves_ground_truth_and_provenance():
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id=(
            "Tuesday-WorkingHours.pcap_ISCX.csv:12345"
        ),
        source_behavior="SSH-Patator",
        scenario_name="ssh_invalid_user_bruteforce",
    )

    assert replay.label == "brute_force"
    assert (
        replay.source_dataset
        == "cic_ids_2017"
    )
    assert replay.source_row_id == (
        "Tuesday-WorkingHours.pcap_ISCX.csv:12345"
    )
    assert (
        replay.source_behavior
        == "SSH-Patator"
    )
    assert (
        replay.scenario_name
        == "ssh_invalid_user_bruteforce"
    )


def test_behavior_replay_is_immutable():
    replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id=(
            "Attack_Data_Master/"
            "Adduser_1/"
            "UAD-Adduser-1-1371.txt"
        ),
        source_behavior="Adduser_1",
        scenario_name="user_added_to_sudo_group",
    )

    with pytest.raises(
        dataclasses.FrozenInstanceError
    ):
        replay.label = "benign"


def test_behavior_replay_contains_no_ml_features():
    replay_fields = {
        field.name
        for field in dataclasses.fields(
            BehaviorReplay
        )
    }

    forbidden_features = {
        "rule_level",
        "rule_frequency",
        "failed_attempts",
        "privileged_target",
        "source_port",
        "destination_port",
        "has_source_ip",
        "has_target_user",
        "has_agent",
        "mitre_id_count",
        "rule_group_count",
        "is_sudo_event",
        "is_account_change_event",
        "is_privilege_group_change",
        "has_command",
    }

    assert (
        replay_fields
        & forbidden_features
    ) == set()


@pytest.mark.parametrize(
    "label",
    [
        "benign",
        "brute_force",
        "privilege_misuse",
    ],
)
def test_behavior_replay_accepts_training_labels(
    label,
):
    replay = BehaviorReplay(
        label=label,
        source_dataset="test_dataset",
        source_row_id="row-1",
        source_behavior="test_behavior",
        scenario_name="test_scenario",
    )

    assert replay.label == label


@pytest.mark.parametrize(
    (
        "label",
        "expected_names",
    ),
    [
        (
            "brute_force",
            (
                "ssh_invalid_user_bruteforce",
                "ssh_root_password_bruteforce",
                "ssh_root_none_bruteforce",
            ),
        ),
        (
            "privilege_misuse",
            (
                "sudo_three_failed_attempts",
                "sudo_unauthorized_user",
                "sudo_command_not_allowed",
                "user_added_to_sudo_group",
            ),
        ),
        (
            "benign",
            (
                "ssh_authentication_success",
                "sudo_non_privileged_success",
                "pam_login_session_opened",
            ),
        ),
    ],
)
def test_scenario_names_for_label_use_existing_wazuh_paths(
    label,
    expected_names,
):
    assert (
        behavior_manifest
        .scenario_names_for_label(
            label
        )
        == expected_names
    )


def test_scenario_names_for_label_rejects_unknown_label():
    with pytest.raises(
        ValueError,
        match="Unsupported training label",
    ):
        behavior_manifest.scenario_names_for_label(
            "unknown"
        )


def test_build_behavior_replay_is_deterministic():
    kwargs = {
        "label": "brute_force",
        "source_dataset": "cic_ids_2017",
        "source_row_id": (
            "Tuesday-WorkingHours.pcap_ISCX.csv:12345"
        ),
        "source_behavior": "SSH-Patator",
        "seed": 42,
    }

    first = (
        behavior_manifest
        .build_behavior_replay(
            **kwargs
        )
    )

    second = (
        behavior_manifest
        .build_behavior_replay(
            **kwargs
        )
    )

    assert first == second


def test_build_behavior_replay_has_stable_selection():
    replay = (
        behavior_manifest
        .build_behavior_replay(
            label="brute_force",
            source_dataset="cic_ids_2017",
            source_row_id=(
                "Tuesday-WorkingHours.pcap_ISCX.csv:12345"
            ),
            source_behavior="SSH-Patator",
            seed=42,
        )
    )

    assert (
        replay.scenario_name
        == "ssh_root_none_bruteforce"
    )


def test_build_behavior_replay_preserves_external_behavior():
    replay = (
        behavior_manifest
        .build_behavior_replay(
            label="brute_force",
            source_dataset="cic_ids_2017",
            source_row_id=(
                "Tuesday-WorkingHours.pcap_ISCX.csv:20000"
            ),
            source_behavior="FTP-Patator",
            seed=42,
        )
    )

    assert replay.label == "brute_force"
    assert (
        replay.source_dataset
        == "cic_ids_2017"
    )
    assert (
        replay.source_behavior
        == "FTP-Patator"
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert (
        scenario.label
        == "brute_force"
    )


@pytest.mark.parametrize(
    (
        "label",
        "source_dataset",
        "source_row_id",
        "source_behavior",
    ),
    [
        (
            "benign",
            "cic_ids_2018",
            "sample.csv:1",
            "Benign",
        ),
        (
            "brute_force",
            "adfa_ld",
            (
                "Attack_Data_Master/"
                "Hydra_SSH_1/"
                "UAD-Hydra-SSH-1-1.txt"
            ),
            "Hydra_SSH_1",
        ),
        (
            "privilege_misuse",
            "cmu_cert_r4_2",
            (
                "answers/r4.2-3/"
                "r4.2-3-BBS0039.csv"
            ),
            "scenario_3",
        ),
    ],
)
def test_selected_wazuh_scenario_matches_ground_truth_label(
    label,
    source_dataset,
    source_row_id,
    source_behavior,
):
    replay = (
        behavior_manifest
        .build_behavior_replay(
            label=label,
            source_dataset=source_dataset,
            source_row_id=source_row_id,
            source_behavior=source_behavior,
            seed=42,
        )
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert scenario.label == label


from training.adapters.adfa_ld import (
    ADFARecord,
)
from training.adapters.cic_ids_2017 import (
    CIC2017Record,
)
from training.adapters.cic_ids_2018 import (
    CIC2018Record,
)
from training.adapters.cmu_insider import (
    CMUInsiderScenario,
)


def test_build_replay_from_cic2017_record():
    record = CIC2017Record(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id=(
            "Tuesday-WorkingHours.pcap_ISCX.csv:100"
        ),
        raw_label="SSH-Patator",
        fields={
            "Label": "SSH-Patator",
        },
    )

    replay = (
        behavior_manifest
        .build_behavior_replay_from_record(
            record,
            seed=42,
        )
    )

    assert replay.label == "brute_force"
    assert (
        replay.source_dataset
        == "cic_ids_2017"
    )
    assert (
        replay.source_row_id
        == record.source_row_id
    )
    assert (
        replay.source_behavior
        == "SSH-Patator"
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert scenario.label == "brute_force"


def test_build_replay_from_cic2018_record():
    record = CIC2018Record(
        label="benign",
        source_dataset="cic_ids_2018",
        source_row_id=(
            "Wednesday-14-02-2018_"
            "TrafficForML_CICFlowMeter.csv:100"
        ),
        raw_label="Benign",
        fields={
            "Label": "Benign",
        },
    )

    replay = (
        behavior_manifest
        .build_behavior_replay_from_record(
            record,
            seed=42,
        )
    )

    assert replay.label == "benign"
    assert (
        replay.source_dataset
        == "cic_ids_2018"
    )
    assert (
        replay.source_behavior
        == "Benign"
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert scenario.label == "benign"


def test_build_replay_from_adfa_record():
    record = ADFARecord(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id=(
            "Attack_Data_Master/"
            "Adduser_1/"
            "UAD-Adduser-1-1371.txt"
        ),
        raw_family="Adduser_1",
        trace="5 4 3 2 1",
    )

    replay = (
        behavior_manifest
        .build_behavior_replay_from_record(
            record,
            seed=42,
        )
    )

    assert (
        replay.label
        == "privilege_misuse"
    )
    assert (
        replay.source_dataset
        == "adfa_ld"
    )
    assert (
        replay.source_behavior
        == "Adduser_1"
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert (
        scenario.label
        == "privilege_misuse"
    )


def test_adfa_adduser_replays_as_privilege_group_change():
    record = ADFARecord(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id=(
            "Attack_Data_Master/"
            "Adduser_6/"
            "UAD-Adduser-6-2462.txt"
        ),
        raw_family="Adduser_6",
        trace="1 2 3",
    )

    replay = (
        behavior_manifest
        .build_behavior_replay_from_record(
            record,
            seed=42,
        )
    )

    assert (
        replay.scenario_name
        == "user_added_to_sudo_group"
    )


def test_build_replay_from_cmu_scenario():
    record = CMUInsiderScenario(
        label="privilege_misuse",
        source_dataset="cmu_cert_r4_2",
        source_row_id=(
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        ),
        source_file=(
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        ),
        dataset="4.2",
        scenario=3,
        insider_user="BBS0039",
        start="08/12/2010 10:24:05",
        end="08/13/2010 19:08:58",
        events=(),
    )

    replay = (
        behavior_manifest
        .build_behavior_replay_from_record(
            record,
            seed=42,
        )
    )

    assert (
        replay.label
        == "privilege_misuse"
    )
    assert (
        replay.source_dataset
        == "cmu_cert_r4_2"
    )
    assert (
        replay.source_behavior
        == "scenario_3"
    )
    assert (
        replay.source_row_id
        == record.source_row_id
    )

    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    assert (
        scenario.label
        == "privilege_misuse"
    )


def test_build_replay_from_record_rejects_unknown_record():
    with pytest.raises(
        TypeError,
        match="Unsupported external behavior record",
    ):
        (
            behavior_manifest
            .build_behavior_replay_from_record(
                object(),
                seed=42,
            )
        )

@pytest.mark.parametrize(
    (
        "record",
        "expected_family",
    ),
    [
        (
            CIC2017Record(
                label="brute_force",
                source_dataset="cic_ids_2017",
                source_row_id="sample.csv:1",
                raw_label="SSH-Patator",
                fields={},
            ),
            "SSH-Patator",
        ),
        (
            CIC2017Record(
                label="brute_force",
                source_dataset="cic_ids_2017",
                source_row_id="sample.csv:2",
                raw_label="FTP-Patator",
                fields={},
            ),
            "FTP-Patator",
        ),
        (
            CIC2018Record(
                label="brute_force",
                source_dataset="cic_ids_2018",
                source_row_id="sample.csv:3",
                raw_label="SSH-Bruteforce",
                fields={},
            ),
            "SSH-Bruteforce",
        ),
        (
            ADFARecord(
                label="brute_force",
                source_dataset="adfa_ld",
                source_row_id=(
                    "Attack_Data_Master/"
                    "Hydra_SSH_7/"
                    "trace.txt"
                ),
                raw_family="Hydra_SSH_7",
                trace="1 2 3",
            ),
            "Hydra_SSH",
        ),
        (
            ADFARecord(
                label="brute_force",
                source_dataset="adfa_ld",
                source_row_id=(
                    "Attack_Data_Master/"
                    "Hydra_FTP_10/"
                    "trace.txt"
                ),
                raw_family="Hydra_FTP_10",
                trace="1 2 3",
            ),
            "Hydra_FTP",
        ),
        (
            ADFARecord(
                label="privilege_misuse",
                source_dataset="adfa_ld",
                source_row_id=(
                    "Attack_Data_Master/"
                    "Adduser_4/"
                    "trace.txt"
                ),
                raw_family="Adduser_4",
                trace="1 2 3",
            ),
            "Adduser",
        ),
        (
            CMUInsiderScenario(
                label="privilege_misuse",
                source_dataset="cmu_cert_r4_2",
                source_row_id=(
                    "answers/r4.2-3/"
                    "r4.2-3-BBS0039.csv"
                ),
                source_file=(
                    "answers/r4.2-3/"
                    "r4.2-3-BBS0039.csv"
                ),
                dataset="4.2",
                scenario=3,
                insider_user="BBS0039",
                start="",
                end="",
                events=(),
            ),
            "scenario_3",
        ),
    ],
)
def test_behavior_family_for_record(
    record,
    expected_family,
):
    assert (
        behavior_manifest
        .behavior_family_for_record(
            record
        )
        == expected_family
    )


def test_behavior_family_for_record_rejects_unknown_record():
    with pytest.raises(
        TypeError,
        match="Unsupported external behavior record",
    ):
        (
            behavior_manifest
            .behavior_family_for_record(
                object()
            )
        )

def _make_cic2017_record(
    row_number: int,
    raw_label: str,
    label: str = "brute_force",
) -> CIC2017Record:
    return CIC2017Record(
        label=label,
        source_dataset="cic_ids_2017",
        source_row_id=(
            f"sample.csv:{row_number}"
        ),
        raw_label=raw_label,
        fields={},
    )


def test_sample_behavior_records_respects_per_group_limit():
    records = [
        _make_cic2017_record(
            row_number,
            "SSH-Patator",
        )
        for row_number in range(
            1,
            11,
        )
    ]

    sampled = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=3,
            seed=42,
        )
    )

    assert len(sampled) == 3


def test_sample_behavior_records_keeps_behavior_families_separate():
    records = [
        *[
            _make_cic2017_record(
                row_number,
                "SSH-Patator",
            )
            for row_number in range(
                1,
                6,
            )
        ],
        *[
            _make_cic2017_record(
                row_number,
                "FTP-Patator",
            )
            for row_number in range(
                101,
                106,
            )
        ],
    ]

    sampled = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=2,
            seed=42,
        )
    )

    families = [
        behavior_manifest
        .behavior_family_for_record(
            record
        )
        for record in sampled
    ]

    assert (
        families.count(
            "SSH-Patator"
        )
        == 2
    )

    assert (
        families.count(
            "FTP-Patator"
        )
        == 2
    )


def test_sample_behavior_records_keeps_all_records_under_limit():
    records = [
        _make_cic2017_record(
            1,
            "SSH-Patator",
        ),
        _make_cic2017_record(
            2,
            "SSH-Patator",
        ),
    ]

    sampled = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=10,
            seed=42,
        )
    )

    assert {
        record.source_row_id
        for record in sampled
    } == {
        "sample.csv:1",
        "sample.csv:2",
    }


def test_sample_behavior_records_is_order_independent():
    records = [
        _make_cic2017_record(
            row_number,
            "SSH-Patator",
        )
        for row_number in range(
            1,
            21,
        )
    ]

    forward = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=5,
            seed=42,
        )
    )

    reverse = (
        behavior_manifest
        .sample_behavior_records(
            reversed(records),
            per_group_limit=5,
            seed=42,
        )
    )

    forward_ids = [
        record.source_row_id
        for record in forward
    ]

    reverse_ids = [
        record.source_row_id
        for record in reverse
    ]

    assert (
        forward_ids
        == reverse_ids
    )


def test_sample_behavior_records_seed_changes_selection():
    records = [
        _make_cic2017_record(
            row_number,
            "SSH-Patator",
        )
        for row_number in range(
            1,
            51,
        )
    ]

    seed_42 = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=5,
            seed=42,
        )
    )

    seed_99 = (
        behavior_manifest
        .sample_behavior_records(
            records,
            per_group_limit=5,
            seed=99,
        )
    )

    ids_42 = {
        record.source_row_id
        for record in seed_42
    }

    ids_99 = {
        record.source_row_id
        for record in seed_99
    }

    assert ids_42 != ids_99


def test_sample_behavior_records_rejects_non_positive_limit():
    with pytest.raises(
        ValueError,
        match="per_group_limit must be positive",
    ):
        (
            behavior_manifest
            .sample_behavior_records(
                [],
                per_group_limit=0,
                seed=42,
            )
        )

def test_build_behavior_manifest_applies_sampling_limit():
    records = [
        _make_cic2017_record(
            row_number,
            "SSH-Patator",
        )
        for row_number in range(
            1,
            21,
        )
    ]

    manifest = (
        behavior_manifest
        .build_behavior_manifest(
            records,
            per_group_limit=4,
            seed=42,
        )
    )

    assert len(manifest) == 4


def test_build_behavior_manifest_is_deterministic():
    records = [
        _make_cic2017_record(
            row_number,
            "SSH-Patator",
        )
        for row_number in range(
            1,
            21,
        )
    ]

    first = (
        behavior_manifest
        .build_behavior_manifest(
            records,
            per_group_limit=5,
            seed=42,
        )
    )

    second = (
        behavior_manifest
        .build_behavior_manifest(
            reversed(records),
            per_group_limit=5,
            seed=42,
        )
    )

    assert first == second


def test_behavior_manifest_excludes_ftp_without_approved_replay_scenario():
    record = _make_cic2017_record(
        row_number=1,
        raw_label="FTP-Patator",
        label="brute_force",
    )

    manifest = (
        behavior_manifest
        .build_behavior_manifest(
            [record],
            per_group_limit=10,
            seed=42,
        )
    )

    assert manifest == []


def test_build_behavior_manifest_preserves_exact_provenance():
    record = ADFARecord(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id=(
            "Attack_Data_Master/"
            "Adduser_7/"
            "trace.txt"
        ),
        raw_family="Adduser_7",
        trace="1 2 3",
    )

    manifest = (
        behavior_manifest
        .build_behavior_manifest(
            [record],
            per_group_limit=10,
            seed=42,
        )
    )

    assert len(manifest) == 1

    replay = manifest[0]

    assert (
        replay.source_dataset
        == "adfa_ld"
    )
    assert (
        replay.source_row_id
        == record.source_row_id
    )
    assert (
        replay.source_behavior
        == "Adduser_7"
    )
    assert (
        replay.label
        == "privilege_misuse"
    )


def test_build_behavior_manifest_only_selects_matching_wazuh_labels():
    records = [
        _make_cic2017_record(
            1,
            "SSH-Patator",
        ),
        CIC2018Record(
            label="benign",
            source_dataset="cic_ids_2018",
            source_row_id="sample.csv:2",
            raw_label="Benign",
            fields={},
        ),
        ADFARecord(
            label="privilege_misuse",
            source_dataset="adfa_ld",
            source_row_id=(
                "Attack_Data_Master/"
                "Adduser_1/"
                "trace.txt"
            ),
            raw_family="Adduser_1",
            trace="1 2 3",
        ),
    ]

    manifest = (
        behavior_manifest
        .build_behavior_manifest(
            records,
            per_group_limit=10,
            seed=42,
        )
    )

    assert len(manifest) == 3

    for replay in manifest:
        scenario = get_scenario_by_name(
            replay.scenario_name
        )

        assert (
            scenario.label
            == replay.label
        )

def test_prepare_behavior_replay_run_preserves_external_provenance():
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id=(
            "Tuesday-WorkingHours.pcap_ISCX.csv:12345"
        ),
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    assert (
        run["scenario_name"]
        == "ssh_root_password_bruteforce"
    )

    assert (
        run["expected_rule_id"]
        == "5763"
    )

    assert (
        run["source_ip"]
        == behavior_manifest
        .behavior_replay_variation(
            replay
        )["source_ip"]
    )

    assert (
        run["label"]
        == "brute_force"
    )

    assert (
        run["source_dataset"]
        == "cic_ids_2017"
    )

    assert (
        run["source_row_id"]
        == replay.source_row_id
    )

    assert (
        run["source_behavior"]
        == "SSH-Patator"
    )

    assert (
        run["wazuh_source_dataset"]
        == "wazuh_lab"
    )

    assert (
        run["wazuh_source_row_id"]
        == (
            "ssh_root_password_"
            "bruteforce_002"
        )
    )

    assert (
        "docker exec"
        in run["injection_command"]
    )

    assert (
        "/var/ossec/logs/"
        "athenasec-test.log"
        in run["injection_command"]
    )

def test_prepare_behavior_replay_run_rejects_label_mismatch():
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="sample.csv:1",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_authentication_success"
        ),
    )

    with pytest.raises(
        ValueError,
        match="Wazuh scenario label mismatch",
    ):
        (
            behavior_manifest
            .prepare_behavior_replay_run(
                replay,
                container_name=(
                    "single-node-wazuh.manager-1"
                ),
                log_path=(
                    "/var/ossec/logs/"
                    "athenasec-test.log"
                ),
            )
        )


def test_prepare_behavior_replay_run_varies_ssh_observation_by_provenance():
    first_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="sample.csv:100",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_invalid_user_bruteforce"
        ),
    )

    second_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="sample.csv:200",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_invalid_user_bruteforce"
        ),
    )

    first_run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            first_replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    second_run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            second_replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    assert (
        first_run["expected_rule_id"]
        == "5712"
    )

    assert (
        second_run["expected_rule_id"]
        == "5712"
    )

    assert (
        first_run["source_ip"]
        != second_run["source_ip"]
    )

    assert (
        first_run["injection_command"]
        != second_run["injection_command"]
    )

    assert (
        first_run["source_ip"]
        in first_run[
            "injection_command"
        ]
    )

    assert (
        second_run["source_ip"]
        in second_run[
            "injection_command"
        ]
    )

def test_prepare_behavior_replay_run_varies_sudo_observation_by_provenance():
    first_replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id="sample:1",
        source_behavior="Adduser_1",
        scenario_name=(
            "sudo_three_failed_attempts"
        ),
    )

    second_replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="adfa_ld",
        source_row_id="sample:3",
        source_behavior="Adduser_1",
        scenario_name=(
            "sudo_three_failed_attempts"
        ),
    )

    first_run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            first_replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    second_run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            second_replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
        )
    )

    assert (
        first_run["expected_rule_id"]
        == "5404"
    )

    assert (
        second_run["expected_rule_id"]
        == "5404"
    )

    assert (
        first_run["injection_command"]
        != second_run["injection_command"]
    )

    commands = {
        first_run[
            "injection_command"
        ],
        second_run[
            "injection_command"
        ],
    }

    assert any(
        "USER=root" in command
        for command in commands
    )

    assert any(
        "USER=backupuser" in command
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


def test_behavior_replay_variant_index_expands_sudo_feature_diversity():
    replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="cmu_cert_r4_2",
        source_row_id=(
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        ),
        source_behavior="scenario_3",
        scenario_name=(
            "sudo_command_not_allowed"
        ),
    )

    variations = [
        behavior_manifest
        .behavior_replay_variation(
            replay,
            variant_index=variant_index,
        )
        for variant_index in range(4)
    ]

    observed_combinations = {
        (
            variation["target_user"],
            variation["include_command"],
        )
        for variation in variations
    }

    assert observed_combinations == {
        ("root", "true"),
        ("root", "false"),
        ("backupuser", "true"),
        ("backupuser", "false"),
    }

def test_prepare_behavior_replay_run_accepts_variant_index():
    replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="cmu_cert_r4_2",
        source_row_id=(
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        ),
        source_behavior="scenario_3",
        scenario_name=(
            "sudo_command_not_allowed"
        ),
    )

    run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
            variant_index=1,
        )
    )

    variation = (
        behavior_manifest
        .behavior_replay_variation(
            replay,
            variant_index=1,
        )
    )

    assert (
        f"USER={variation['target_user']}"
        in run["injection_command"]
    )

    if (
        variation["include_command"]
        == "true"
    ):
        assert (
            "COMMAND=/bin/bash"
            in run["injection_command"]
        )
    else:
        assert (
            "COMMAND=/bin/bash"
            not in run["injection_command"]
        )

    assert (
        run["source_dataset"]
        == "cmu_cert_r4_2"
    )

    assert (
        run["source_row_id"]
        == replay.source_row_id
    )

def test_prepare_behavior_replay_run_preserves_variant_index():
    replay = BehaviorReplay(
        label="privilege_misuse",
        source_dataset="cmu_cert_r4_2",
        source_row_id=(
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        ),
        source_behavior="scenario_3",
        scenario_name=(
            "sudo_command_not_allowed"
        ),
    )

    run = (
        behavior_manifest
        .prepare_behavior_replay_run(
            replay,
            container_name=(
                "single-node-wazuh.manager-1"
            ),
            log_path=(
                "/var/ossec/logs/"
                "athenasec-test.log"
            ),
            variant_index=3,
        )
    )

    assert run["variant_index"] == 3
