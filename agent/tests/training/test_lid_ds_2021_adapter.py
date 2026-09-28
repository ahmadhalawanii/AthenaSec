import json
import zipfile

from training.adapters import lid_ds_2021
from training.adapters.lid_ds_2021 import (
    iter_lid_ds_2021_records,
)


def _write_archive(
    path,
    metadata,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:
        archive.writestr(
            f"{path.stem}.json",
            json.dumps(metadata),
        )


def test_normal_recording_maps_to_benign(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "Bruteforce_CWE-307"
        / "test"
        / "normal"
        / "normal.zip"
    )

    _write_archive(
        archive_path,
        {
            "exploit": False,
            "exploit_name": "default",
            "time": {
                "exploit": [],
            },
        },
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.label == "benign"
    assert (
        record.source_dataset
        == "lid_ds_2021"
    )
    assert record.raw_label == "normal"


def test_bruteforce_attack_maps_to_brute_force(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "Bruteforce_CWE-307"
        / "test"
        / "normal_and_attack"
        / "brute.zip"
    )

    _write_archive(
        archive_path,
        {
            "exploit": True,
            "image": "victim_bruteforce",
            "time": {
                "exploit": [
                    {
                        "absolute": 1.0,
                        "name": "attack",
                        "source": "SYSDIG",
                    }
                ],
            },
        },
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.label == "brute_force"
    assert (
        record.raw_label
        == "Bruteforce_CWE-307"
    )


def test_cve_only_privilege_escalation_maps_to_privilege_misuse(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "CVE-2017-12635_6"
        / "test"
        / "normal_and_attack"
        / "cve.zip"
    )

    _write_archive(
        archive_path,
        {
            "exploit": True,
            "time": {
                "exploit": [
                    {
                        "absolute": 1.0,
                        "name": "port-scan",
                        "source": "TCPDUMP",
                    },
                    {
                        "absolute": 2.0,
                        "name": "privilege-escalation",
                        "source": "SYSDIG",
                    },
                    {
                        "absolute": 3.0,
                        "name": "remote-code",
                        "source": "TCPDUMP",
                    },
                ],
            },
        },
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.label
        == "privilege_misuse"
    )
    assert (
        record.raw_label
        == "privilege-escalation"
    )


def test_cve_port_scan_and_remote_code_are_not_emitted(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "CVE-2017-12635_6"
        / "test"
        / "normal_and_attack"
        / "cve.zip"
    )

    _write_archive(
        archive_path,
        {
            "exploit": True,
            "time": {
                "exploit": [
                    {
                        "absolute": 1.0,
                        "name": "port-scan",
                        "source": "TCPDUMP",
                    },
                    {
                        "absolute": 2.0,
                        "name": "remote-code",
                        "source": "TCPDUMP",
                    },
                ],
            },
        },
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert records == []


def test_source_row_id_preserves_archive_and_stage(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "CVE-2017-12635_6"
        / "test"
        / "normal_and_attack"
        / "cve.zip"
    )

    _write_archive(
        archive_path,
        {
            "exploit": True,
            "time": {
                "exploit": [
                    {
                        "absolute": 1.0,
                        "name": "port-scan",
                        "source": "TCPDUMP",
                    },
                    {
                        "absolute": 2.0,
                        "name": "privilege-escalation",
                        "source": "SYSDIG",
                    },
                ],
            },
        },
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert records[0].source_row_id == (
        "CVE-2017-12635_6/"
        "test/"
        "normal_and_attack/"
        "cve.zip:exploit:1"
    )


def test_metadata_is_preserved(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "Bruteforce_CWE-307"
        / "test"
        / "normal_and_attack"
        / "brute.zip"
    )

    metadata = {
        "exploit": True,
        "image": "victim_bruteforce",
        "time": {
            "exploit": [
                {
                    "absolute": 1.0,
                    "name": "attack",
                    "source": "SYSDIG",
                }
            ],
        },
    }

    _write_archive(
        archive_path,
        metadata,
    )

    records = list(
        iter_lid_ds_2021_records(
            tmp_path
        )
    )

    assert records[0].fields == metadata