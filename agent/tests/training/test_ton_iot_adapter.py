from training.adapters import ton_iot
from training.adapters.ton_iot import (
    map_ton_iot_label,
)


def test_normal_maps_to_benign():
    assert (
        map_ton_iot_label(
            "normal"
        )
        == "benign"
    )


def test_password_maps_to_brute_force():
    assert (
        map_ton_iot_label(
            "password"
        )
        == "brute_force"
    )


def test_unrelated_attack_is_ignored():
    assert (
        map_ton_iot_label(
            "ddos"
        )
        is None
    )


def test_unknown_type_is_ignored():
    assert (
        map_ton_iot_label(
            "something_new"
        )
        is None
    )


def test_type_whitespace_is_normalized():
    assert (
        map_ton_iot_label(
            "  password  "
        )
        == "brute_force"
    )


def test_iter_ton_iot_records_keeps_supported_rows(
    tmp_path,
):
    csv_path = tmp_path / "train_test_network.csv"

    csv_path.write_text(
        (
            "src_ip,dst_ip,label,type\n"
            "10.0.0.1,10.0.0.2,0,normal\n"
            "10.0.0.3,10.0.0.4,1,password\n"
            "10.0.0.5,10.0.0.6,1,ddos\n"
            "10.0.0.7,10.0.0.8,0,normal\n"
        ),
        encoding="utf-8",
    )

    records = list(
        ton_iot.iter_ton_iot_records(
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
        "ton_iot",
        "ton_iot",
        "ton_iot",
    ]

    assert [
        record.source_row_id
        for record in records
    ] == [
        "train_test_network.csv:1",
        "train_test_network.csv:2",
        "train_test_network.csv:4",
    ]


def test_iter_ton_iot_records_preserves_type_and_raw_data(
    tmp_path,
):
    csv_path = tmp_path / "train_test_network.csv"

    csv_path.write_text(
        (
            "src_ip,dst_ip,label,type\n"
            "10.0.0.3,10.0.0.4,1,password\n"
        ),
        encoding="utf-8",
    )

    records = list(
        ton_iot.iter_ton_iot_records(
            csv_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.raw_label == "password"

    assert record.fields == {
        "src_ip": "10.0.0.3",
        "dst_ip": "10.0.0.4",
        "label": "1",
        "type": "password",
    }