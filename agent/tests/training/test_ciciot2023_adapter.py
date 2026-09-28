from training.adapters import ciciot2023
from training.adapters.ciciot2023 import (
    map_ciciot2023_label,
)


def test_benign_maps_to_benign():
    assert (
        map_ciciot2023_label(
            "BENIGN"
        )
        == "benign"
    )


def test_dictionary_bruteforce_maps_to_brute_force():
    assert (
        map_ciciot2023_label(
            "DICTIONARYBRUTEFORCE"
        )
        == "brute_force"
    )


def test_unrelated_attack_is_ignored():
    assert (
        map_ciciot2023_label(
            "DDOS-UDP_FLOOD"
        )
        is None
    )


def test_unknown_label_is_ignored():
    assert (
        map_ciciot2023_label(
            "Something New"
        )
        is None
    )


def test_label_whitespace_is_normalized():
    assert (
        map_ciciot2023_label(
            "  DICTIONARYBRUTEFORCE  "
        )
        == "brute_force"
    )


def test_iter_ciciot2023_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "Merged01.csv"

    csv_path.write_text(
        (
            "flow_duration,Header_Length,Label\n"
            "10,20,BENIGN\n"
            "30,40,DICTIONARYBRUTEFORCE\n"
            "50,60,DDOS-UDP_FLOOD\n"
            "70,80,BENIGN\n"
        ),
        encoding="utf-8",
    )

    records = list(
        ciciot2023.iter_ciciot2023_records(
            csv_path
        )
    )

    assert [
        record.label
        for record in records
    ] == [
        "benign",
        "brute_force",
        "benign",
    ]

    assert [
        record.source_dataset
        for record in records
    ] == [
        "cic_iot_2023",
        "cic_iot_2023",
        "cic_iot_2023",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "Merged01.csv:1",
        "Merged01.csv:2",
        "Merged01.csv:4",
    ]


def test_iter_ciciot2023_records_preserves_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "Merged01.csv"

    csv_path.write_text(
        (
            "flow_duration,Header_Length,Label\n"
            "30,40,DICTIONARYBRUTEFORCE\n"
        ),
        encoding="utf-8",
    )

    records = list(
        ciciot2023.iter_ciciot2023_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.raw_label
        == "DICTIONARYBRUTEFORCE"
    )

    assert record.fields == {
        "flow_duration": "30",
        "Header_Length": "40",
        "Label": "DICTIONARYBRUTEFORCE",
    }