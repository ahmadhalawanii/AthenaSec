from training.adapters import cic_ids_2018
from training.adapters.cic_ids_2018 import (
    map_cic2018_label,
)


def test_benign_maps_to_benign():
    assert (
        map_cic2018_label(
            "Benign"
        )
        == "benign"
    )


def test_ftp_bruteforce_maps_to_brute_force():
    assert (
        map_cic2018_label(
            "FTP-BruteForce"
        )
        == "brute_force"
    )


def test_ssh_bruteforce_maps_to_brute_force():
    assert (
        map_cic2018_label(
            "SSH-Bruteforce"
        )
        == "brute_force"
    )


def test_unknown_label_is_ignored():
    assert (
        map_cic2018_label(
            "DDoS attacks-LOIC-HTTP"
        )
        is None
    )


def test_label_whitespace_is_normalized():
    assert (
        map_cic2018_label(
            "  SSH-Bruteforce  "
        )
        == "brute_force"
    )


def test_iter_cic2018_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "Wednesday-test.csv"

    csv_path.write_text(
        (
            "Dst Port,Flow Duration,Label\n"
            "80,1000,Benign\n"
            "21,2000,FTP-BruteForce\n"
            "443,3000,DDoS attacks-LOIC-HTTP\n"
            "22,4000,SSH-Bruteforce\n"
        ),
        encoding="utf-8",
    )

    records = list(
        cic_ids_2018.iter_cic2018_records(
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
        "cic_ids_2018",
        "cic_ids_2018",
        "cic_ids_2018",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "Wednesday-test.csv:1",
        "Wednesday-test.csv:2",
        "Wednesday-test.csv:4",
    ]


def test_iter_cic2018_records_normalizes_headers_and_preserves_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "Wednesday-test.csv"

    csv_path.write_text(
        (
            " Dst Port , Flow Duration , Label \n"
            "22,1500,SSH-Bruteforce\n"
        ),
        encoding="utf-8",
    )

    records = list(
        cic_ids_2018.iter_cic2018_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.raw_label == "SSH-Bruteforce"

    assert record.fields == {
        "Dst Port": "22",
        "Flow Duration": "1500",
        "Label": "SSH-Bruteforce",
    }