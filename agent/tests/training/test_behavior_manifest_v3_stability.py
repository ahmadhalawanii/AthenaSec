from training import behavior_manifest


def test_expanded_benign_catalog_preserves_v2_assignment():
    replay = (
        behavior_manifest.build_behavior_replay(
            label="benign",
            source_dataset="adfa_ld",
            source_row_id=(
                "Training_Data_Master/"
                "UTD-0143.txt"
            ),
            source_behavior=(
                "Training_Data_Master"
            ),
            seed=42,
        )
    )

    assert (
        replay.scenario_name
        == "sudo_non_privileged_success"
    )


def test_expanded_privilege_catalog_preserves_v2_assignment():
    replay = (
        behavior_manifest.build_behavior_replay(
            label="privilege_misuse",
            source_dataset="cmu_cert_r4_2",
            source_row_id=(
                "answers/r4.2-3/"
                "r4.2-3-MPM0220.csv"
            ),
            source_behavior="scenario_3",
            seed=42,
        )
    )

    assert (
        replay.scenario_name
        == "sudo_command_not_allowed"
    )


def test_brute_force_assignment_remains_unchanged():
    replay = (
        behavior_manifest.build_behavior_replay(
            label="brute_force",
            source_dataset="cic_ids_2017",
            source_row_id=(
                "Tuesday-WorkingHours."
                "pcap_ISCX.csv:12345"
            ),
            source_behavior="SSH-Patator",
            seed=42,
        )
    )

    assert (
        replay.scenario_name
        == "ssh_root_none_bruteforce"
    )