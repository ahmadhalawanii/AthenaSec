import json
from pathlib import Path

from training.behavior_manifest import BehaviorReplay
from training import manifest_generation


def test_generate_behavior_replay_manifest_combines_all_dataset_sources(
    tmp_path: Path,
    monkeypatch,
):
    cic2017_dir = tmp_path / "cic2017"
    cic2018_dir = tmp_path / "cic2018"
    adfa_root = tmp_path / "adfa"
    cmu_archive = tmp_path / "r4.2.tar.bz2"

    ciciot2023_dir = tmp_path / "ciciot2023"
    hikari_dir = tmp_path / "hikari"
    lid_ds_root = tmp_path / "lid_ds"
    ton_iot_dir = tmp_path / "ton_iot"
    x_iiotid_csv = tmp_path / "x_iiotid.csv"

    output_path = (
        tmp_path
        / "behavior_replay_manifest.jsonl"
    )

    cic2017_dir.mkdir()
    cic2018_dir.mkdir()
    adfa_root.mkdir()

    ciciot2023_dir.mkdir()
    hikari_dir.mkdir()
    lid_ds_root.mkdir()
    ton_iot_dir.mkdir()

    first_2017 = (
        cic2017_dir / "a.csv"
    )
    second_2017 = (
        cic2017_dir / "b.csv"
    )
    only_2018 = (
        cic2018_dir / "c.csv"
    )

    ciciot2023_csv = (
        ciciot2023_dir
        / "Merged01.csv"
    )
    hikari_csv = (
        hikari_dir
        / "HIKARI.csv"
    )
    ton_iot_csv = (
        ton_iot_dir
        / "Train_Test_datasets"
        / "Train_Test_Network_dataset"
        / "train_test_network.csv"
    )

    ton_iot_csv.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    first_2017.write_text(
        "",
        encoding="utf-8",
    )
    second_2017.write_text(
        "",
        encoding="utf-8",
    )
    only_2018.write_text(
        "",
        encoding="utf-8",
    )

    ciciot2023_csv.write_text(
        "",
        encoding="utf-8",
    )
    hikari_csv.write_text(
        "",
        encoding="utf-8",
    )
    ton_iot_csv.write_text(
        "",
        encoding="utf-8",
    )
    x_iiotid_csv.write_text(
        "",
        encoding="utf-8",
    )

    cmu_archive.write_bytes(
        b"fixture"
    )

    calls = []

    def fake_cic2017(path):
        calls.append(
            (
                "cic2017",
                Path(path).name,
            )
        )
        return [
            f"2017:{Path(path).name}"
        ]

    def fake_cic2018(path):
        calls.append(
            (
                "cic2018",
                Path(path).name,
            )
        )
        return [
            f"2018:{Path(path).name}"
        ]

    def fake_adfa(path):
        calls.append(
            (
                "adfa",
                Path(path).name,
            )
        )
        return [
            "adfa-record"
        ]

    def fake_cmu(path):
        calls.append(
            (
                "cmu",
                Path(path).name,
            )
        )
        return [
            "cmu-record"
        ]

    def fake_ciciot2023(path):
        calls.append(
            (
                "ciciot2023",
                Path(path).name,
            )
        )
        return [
            "ciciot2023-record"
        ]

    def fake_hikari(path):
        calls.append(
            (
                "hikari",
                Path(path).name,
            )
        )
        return [
            "hikari-record"
        ]

    def fake_lid_ds(path):
        calls.append(
            (
                "lid_ds",
                Path(path).name,
            )
        )
        return [
            "lid-ds-record"
        ]

    def fake_ton_iot(path):
        calls.append(
            (
                "ton_iot",
                Path(path).name,
            )
        )
        return [
            "ton-iot-record"
        ]

    def fake_x_iiotid(path):
        calls.append(
            (
                "x_iiotid",
                Path(path).name,
            )
        )
        return [
            "x-iiotid-record"
        ]

    captured = {}

    def fake_build_behavior_manifest(
        records,
        *,
        per_group_limit,
        seed,
    ):
        captured["records"] = list(
            records
        )
        captured[
            "per_group_limit"
        ] = per_group_limit
        captured["seed"] = seed

        return [
            BehaviorReplay(
                label="benign",
                source_dataset=(
                    "cic_ids_2017"
                ),
                source_row_id=(
                    "a.csv:1"
                ),
                source_behavior=(
                    "BENIGN"
                ),
                scenario_name=(
                    "ssh_authentication_success"
                ),
            ),
            BehaviorReplay(
                label="privilege_misuse",
                source_dataset=(
                    "cmu_insider"
                ),
                source_row_id=(
                    "scenario-3"
                ),
                source_behavior=(
                    "scenario_3"
                ),
                scenario_name=(
                    "sudo_unauthorized_user"
                ),
            ),
        ]

    monkeypatch.setattr(
        manifest_generation,
        "iter_cic2017_records",
        fake_cic2017,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_cic2018_records",
        fake_cic2018,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_adfa_records",
        fake_adfa,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_cmu_scenarios",
        fake_cmu,
    )

    monkeypatch.setattr(
        manifest_generation,
        "iter_ciciot2023_records",
        fake_ciciot2023,
        raising=False,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_hikari_2021_records",
        fake_hikari,
        raising=False,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_lid_ds_2021_records",
        fake_lid_ds,
        raising=False,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_ton_iot_records",
        fake_ton_iot,
        raising=False,
    )
    monkeypatch.setattr(
        manifest_generation,
        "iter_x_iiotid_records",
        fake_x_iiotid,
        raising=False,
    )

    monkeypatch.setattr(
        manifest_generation,
        "build_behavior_manifest",
        fake_build_behavior_manifest,
    )

    manifest = (
        manifest_generation
        .generate_behavior_replay_manifest(
            cic2017_dir=cic2017_dir,
            cic2018_dir=cic2018_dir,
            adfa_root=adfa_root,
            cmu_archive=cmu_archive,
            ciciot2023_dir=(
                ciciot2023_dir
            ),
            hikari_dir=hikari_dir,
            lid_ds_root=lid_ds_root,
            ton_iot_dir=ton_iot_dir,
            x_iiotid_csv=(
                x_iiotid_csv
            ),
            output_path=output_path,
            per_group_limit=10,
            seed=42,
        )
    )

    assert calls == [
        (
            "cic2017",
            "a.csv",
        ),
        (
            "cic2017",
            "b.csv",
        ),
        (
            "cic2018",
            "c.csv",
        ),
        (
            "adfa",
            "adfa",
        ),
        (
            "cmu",
            "r4.2.tar.bz2",
        ),
        (
            "ciciot2023",
            "Merged01.csv",
        ),
        (
            "hikari",
            "HIKARI.csv",
        ),
        (
            "lid_ds",
            "lid_ds",
        ),
        (
            "ton_iot",
            "train_test_network.csv",
        ),
        (
            "x_iiotid",
            "x_iiotid.csv",
        ),
    ]

    assert captured["records"] == [
        "2017:a.csv",
        "2017:b.csv",
        "2018:c.csv",
        "adfa-record",
        "cmu-record",
        "ciciot2023-record",
        "hikari-record",
        "lid-ds-record",
        "ton-iot-record",
        "x-iiotid-record",
    ]

    assert (
        captured["per_group_limit"]
        == 10
    )
    assert captured["seed"] == 42

    assert len(manifest) == 2

    written = [
        json.loads(line)
        for line
        in output_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert written == [
        {
            "label": "benign",
            "source_dataset": (
                "cic_ids_2017"
            ),
            "source_row_id": (
                "a.csv:1"
            ),
            "source_behavior": (
                "BENIGN"
            ),
            "scenario_name": (
                "ssh_authentication_success"
            ),
        },
        {
            "label": (
                "privilege_misuse"
            ),
            "source_dataset": (
                "cmu_insider"
            ),
            "source_row_id": (
                "scenario-3"
            ),
            "source_behavior": (
                "scenario_3"
            ),
            "scenario_name": (
                "sudo_unauthorized_user"
            ),
        },
    ]

def test_manifest_generation_only_reads_validated_ton_iot_sources(
    tmp_path: Path,
    monkeypatch,
):
    ton_iot_root = tmp_path / "ton_iot"

    validated_paths = [
        (
            "Train_Test_datasets/"
            "Train_Test_Network_dataset/"
            "train_test_network.csv"
        ),
        (
            "Train_Test_datasets/"
            "Train_Test_Linux_dataset/"
            "Train_Test_Linux_process.csv"
        ),
        (
            "Train_Test_datasets/"
            "Train_Test_Windows_dataset/"
            "Train_Test_Windows_10.csv"
        ),
        (
            "Train_Test_datasets/"
            "Train_Test_Windows_dataset/"
            "Train_Test_Windows_7.csv"
        ),
    ]

    for relative_path in validated_paths:
        path = ton_iot_root / relative_path

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            "",
            encoding="utf-8",
        )

    unvalidated = (
        ton_iot_root
        / "Train_Test_datasets"
        / "Train_Test_IoT_dataset"
        / "Train_Test_IoT_Fridge.csv"
    )

    unvalidated.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    unvalidated.write_text(
        "",
        encoding="utf-8",
    )

    calls = []

    def fake_ton_iot(path):
        calls.append(
            Path(path)
            .relative_to(ton_iot_root)
            .as_posix()
        )
        return []

    monkeypatch.setattr(
        manifest_generation,
        "iter_ton_iot_records",
        fake_ton_iot,
    )

    records = []

    manifest_generation._extend_ton_iot_records(
        records,
        ton_iot_root,
    )

    assert calls == validated_paths
    assert records == []