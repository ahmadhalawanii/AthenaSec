from training.adapters import hikari_2021
from training.adapters.hikari_2021 import (
    map_hikari_2021_label,
)


def test_benign_maps_to_benign():
    assert (
        map_hikari_2021_label(
            "Benign"
        )
        == "benign"
    )


def test_bruteforce_maps_to_brute_force():
    assert (
        map_hikari_2021_label(
            "Bruteforce"
        )
        == "brute_force"
    )


def test_bruteforce_xml_maps_to_brute_force():
    assert (
        map_hikari_2021_label(
            "Bruteforce-XML"
        )
        == "brute_force"
    )


def test_background_is_ignored():
    assert (
        map_hikari_2021_label(
            "Background"
        )
        is None
    )


def test_unrelated_attack_is_ignored():
    assert (
        map_hikari_2021_label(
            "Probing"
        )
        is None
    )


def test_label_whitespace_is_normalized():
    assert (
        map_hikari_2021_label(
            "  Bruteforce-XML  "
        )
        == "brute_force"
    )


def test_iter_hikari_2021_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "ALLFLOWMETER_HIKARI2021.csv"

    csv_path.write_text(
        (
            "flow_id,traffic_category,Label\n"
            "1,Benign,0\n"
            "2,Bruteforce,1\n"
            "3,Background,0\n"
            "4,Bruteforce-XML,1\n"
            "5,Probing,1\n"
        ),
        encoding="utf-8",
    )

    records = list(
        hikari_2021.iter_hikari_2021_records(
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
        "hikari_2021",
        "hikari_2021",
        "hikari_2021",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "ALLFLOWMETER_HIKARI2021.csv:1",
        "ALLFLOWMETER_HIKARI2021.csv:2",
        "ALLFLOWMETER_HIKARI2021.csv:4",
    ]


def test_iter_hikari_2021_records_preserves_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "ALLFLOWMETER_HIKARI2021.csv"

    csv_path.write_text(
        (
            "flow_id,traffic_category,Label\n"
            "2,Bruteforce-XML,1\n"
        ),
        encoding="utf-8",
    )

    records = list(
        hikari_2021.iter_hikari_2021_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.raw_label
        == "Bruteforce-XML"
    )

    assert record.fields == {
        "flow_id": "2",
        "traffic_category": "Bruteforce-XML",
        "Label": "1",
    }