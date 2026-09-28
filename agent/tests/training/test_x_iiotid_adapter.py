from training.adapters import x_iiotid
from training.adapters.x_iiotid import (
    map_x_iiotid_label,
)


def test_normal_maps_to_benign():
    assert (
        map_x_iiotid_label(
            "Normal"
        )
        == "benign"
    )


def test_bruteforce_maps_to_brute_force():
    assert (
        map_x_iiotid_label(
            "BruteForce"
        )
        == "brute_force"
    )


def test_dictionary_maps_to_brute_force():
    assert (
        map_x_iiotid_label(
            "Dictionary"
        )
        == "brute_force"
    )


def test_insider_malcious_maps_to_privilege_misuse():
    assert (
        map_x_iiotid_label(
            "insider_malcious"
        )
        == "privilege_misuse"
    )


def test_unrelated_attack_is_ignored():
    assert (
        map_x_iiotid_label(
            "RDOS"
        )
        is None
    )


def test_unknown_label_is_ignored():
    assert (
        map_x_iiotid_label(
            "Something New"
        )
        is None
    )


def test_label_whitespace_is_normalized():
    assert (
        map_x_iiotid_label(
            "  insider_malcious  "
        )
        == "privilege_misuse"
    )


def test_iter_x_iiotid_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "X-IIoTID dataset.csv"

    csv_path.write_text(
        (
            "Scr_IP,Des_IP,class1,class2,class3\n"
            "10.0.0.1,10.0.0.2,Normal,Normal,Normal\n"
            "10.0.0.3,10.0.0.4,BruteForce,Weaponization,Attack\n"
            "10.0.0.5,10.0.0.6,RDOS,RDOS,Attack\n"
            "10.0.0.7,10.0.0.8,Dictionary,Weaponization,Attack\n"
            "10.0.0.9,10.0.0.10,insider_malcious,Weaponization,Attack\n"
        ),
        encoding="utf-8",
    )

    records = list(
        x_iiotid.iter_x_iiotid_records(
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
        "privilege_misuse",
    ]

    assert [
        record.source_dataset
        for record in records
    ] == [
        "x_iiotid",
        "x_iiotid",
        "x_iiotid",
        "x_iiotid",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "X-IIoTID dataset.csv:1",
        "X-IIoTID dataset.csv:2",
        "X-IIoTID dataset.csv:4",
        "X-IIoTID dataset.csv:5",
    ]


def test_iter_x_iiotid_records_preserves_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "X-IIoTID dataset.csv"

    csv_path.write_text(
        (
            "Scr_IP,Des_IP,class1,class2,class3\n"
            "10.0.0.9,10.0.0.10,insider_malcious,Weaponization,Attack\n"
        ),
        encoding="utf-8",
    )

    records = list(
        x_iiotid.iter_x_iiotid_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.raw_label
        == "insider_malcious"
    )

    assert record.fields == {
        "Scr_IP": "10.0.0.9",
        "Des_IP": "10.0.0.10",
        "class1": "insider_malcious",
        "class2": "Weaponization",
        "class3": "Attack",
    }