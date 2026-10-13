from collections import Counter

from training.adapters import adfa_ld
from training.adapters.adfa_ld import (
    map_adfa_attack_family,
)


def test_hydra_ftp_maps_to_brute_force():
    assert (
        map_adfa_attack_family(
            "Hydra_FTP"
        )
        == "brute_force"
    )


def test_hydra_ssh_maps_to_brute_force():
    assert (
        map_adfa_attack_family(
            "Hydra_SSH"
        )
        == "brute_force"
    )


def test_adduser_maps_to_privilege_misuse():
    assert (
        map_adfa_attack_family(
            "Adduser"
        )
        == "privilege_misuse"
    )


def test_meterpreter_is_ignored():
    assert (
        map_adfa_attack_family(
            "Meterpreter"
        )
        is None
    )


def test_java_meterpreter_is_ignored():
    assert (
        map_adfa_attack_family(
            "Java_Meterpreter"
        )
        is None
    )


def test_web_shell_is_ignored():
    assert (
        map_adfa_attack_family(
            "Web_Shell"
        )
        is None
    )


def test_numbered_attack_folder_is_normalized():
    assert (
        map_adfa_attack_family(
            "Hydra_SSH_7"
        )
        == "brute_force"
    )


def test_whitespace_is_normalized():
    assert (
        map_adfa_attack_family(
            "  Adduser_3  "
        )
        == "privilege_misuse"
    )


def test_iter_adfa_records_keeps_supported_traces(
    tmp_path,
):
    root = tmp_path / "ADFA-LD"

    training_dir = (
        root
        / "Training_Data_Master"
    )
    validation_dir = (
        root
        / "Validation_Data_Master"
    )
    hydra_dir = (
        root
        / "Attack_Data_Master"
        / "Hydra_SSH_1"
    )
    adduser_dir = (
        root
        / "Attack_Data_Master"
        / "Adduser_2"
    )
    ignored_dir = (
        root
        / "Attack_Data_Master"
        / "Meterpreter_1"
    )

    for directory in (
        training_dir,
        validation_dir,
        hydra_dir,
        adduser_dir,
        ignored_dir,
    ):
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    (
        training_dir
        / "UTD-0001.txt"
    ).write_text(
        "1 2 3",
        encoding="utf-8",
    )

    (
        validation_dir
        / "UVD-0001.txt"
    ).write_text(
        "4 5 6",
        encoding="utf-8",
    )

    (
        hydra_dir
        / "UAD-Hydra-SSH-1-1371.txt"
    ).write_text(
        "7 8 9",
        encoding="utf-8",
    )

    (
        adduser_dir
        / "UAD-Adduser-2-1371.txt"
    ).write_text(
        "10 11 12",
        encoding="utf-8",
    )

    (
        ignored_dir
        / "UAD-Meterpreter-1-1371.txt"
    ).write_text(
        "13 14 15",
        encoding="utf-8",
    )

    records = list(
        adfa_ld.iter_adfa_records(
            root
        )
    )

    counts = Counter(
        record.label
        for record in records
    )

    assert counts == {
        "benign": 2,
        "brute_force": 1,
        "privilege_misuse": 1,
    }

    assert len(records) == 4

    assert all(
        record.source_dataset
        == "adfa_ld"
        for record in records
    )


def test_iter_adfa_records_preserves_trace_and_provenance(
    tmp_path,
):
    root = tmp_path / "ADFA-LD"

    trace_dir = (
        root
        / "Attack_Data_Master"
        / "Hydra_SSH_7"
    )

    trace_dir.mkdir(
        parents=True
    )

    trace_path = (
        trace_dir
        / "UAD-Hydra-SSH-7-1371.txt"
    )

    trace_path.write_text(
        "1 2 3 4 5 6\n",
        encoding="utf-8",
    )

    records = list(
        adfa_ld.iter_adfa_records(
            root
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.label == "brute_force"

    assert (
        record.raw_family
        == "Hydra_SSH_7"
    )

    assert (
        record.source_row_id
        == (
            "Attack_Data_Master/"
            "Hydra_SSH_7/"
            "UAD-Hydra-SSH-7-1371.txt"
        )
    )

    assert record.trace == (
        "1 2 3 4 5 6\n"
    )