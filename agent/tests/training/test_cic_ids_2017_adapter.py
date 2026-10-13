from training.adapters import cic_ids_2017
from training.adapters.cic_ids_2017 import (
    map_cic2017_label,
)

def test_benign_maps_to_benign():
    assert (
        map_cic2017_label(
            "BENIGN"
        )
        == "benign"
    )


def test_ftp_patator_maps_to_brute_force():
    assert (
        map_cic2017_label(
            "FTP-Patator"
        )
        == "brute_force"
    )


def test_ssh_patator_maps_to_brute_force():
    assert (
        map_cic2017_label(
            "SSH-Patator"
        )
        == "brute_force"
    )


def test_unrelated_attack_label_is_ignored():
    assert (
        map_cic2017_label(
            "DDoS"
        )
        is None
    )


def test_unknown_label_is_ignored():
    assert (
        map_cic2017_label(
            "Something New"
        )
        is None
    )


def test_label_whitespace_is_normalized():
    assert (
        map_cic2017_label(
            "  SSH-Patator  "
        )
        == "brute_force"
    )


def test_iter_cic2017_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "Tuesday-test.csv"

    csv_path.write_text(
        (
            " Destination Port, Flow Duration, Label\n"
            "80,1000,BENIGN\n"
            "21,2000,FTP-Patator\n"
            "443,3000,DDoS\n"
            "22,4000,SSH-Patator\n"
        ),
        encoding="utf-8",
    )

    records = list(
        cic_ids_2017.iter_cic2017_records(
            csv_path
        )
    )

    assert [
        record.label
        for record in records
    ] == [
        "benign",
        "brute_force",
        "brute_force",
    ]

    assert [
        record.source_dataset
        for record in records
    ] == [
        "cic_ids_2017",
        "cic_ids_2017",
        "cic_ids_2017",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "Tuesday-test.csv:1",
        "Tuesday-test.csv:2",
        "Tuesday-test.csv:4",
    ]


def test_iter_cic2017_records_normalizes_headers_and_preserves_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "Tuesday-test.csv"

    csv_path.write_text(
        (
            " Destination Port, Flow Duration, Label\n"
            "22,1500,SSH-Patator\n"
        ),
        encoding="utf-8",
    )

    records = list(
        cic_ids_2017.iter_cic2017_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.raw_label == "SSH-Patator"

    assert record.fields == {
        "Destination Port": "22",
        "Flow Duration": "1500",
        "Label": "SSH-Patator",
    }