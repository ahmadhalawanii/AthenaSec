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
    output_path = tmp_path / "behavior_replay_manifest.jsonl"

    cic2017_dir.mkdir()
    cic2018_dir.mkdir()
    adfa_root.mkdir()

    first_2017 = cic2017_dir / "a.csv"
    second_2017 = cic2017_dir / "b.csv"
    only_2018 = cic2018_dir / "c.csv"

    first_2017.write_text("", encoding="utf-8")
    second_2017.write_text("", encoding="utf-8")
    only_2018.write_text("", encoding="utf-8")
    cmu_archive.write_bytes(b"fixture")

    calls = []

    def fake_cic2017(path):
        calls.append(("cic2017", Path(path).name))
        return [f"2017:{Path(path).name}"]

    def fake_cic2018(path):
        calls.append(("cic2018", Path(path).name))
        return [f"2018:{Path(path).name}"]

    def fake_adfa(path):
        calls.append(("adfa", Path(path).name))
        return ["adfa-record"]

    def fake_cmu(path):
        calls.append(("cmu", Path(path).name))
        return ["cmu-record"]

    captured = {}

    def fake_build_behavior_manifest(
        records,
        *,
        per_group_limit,
        seed,
    ):
        captured["records"] = list(records)
        captured["per_group_limit"] = per_group_limit
        captured["seed"] = seed

        return [
            BehaviorReplay(
                label="benign",
                source_dataset="cic_ids_2017",
                source_row_id="a.csv:1",
                source_behavior="BENIGN",
                scenario_name="ssh_authentication_success",
            ),
            BehaviorReplay(
                label="privilege_misuse",
                source_dataset="cmu_insider",
                source_row_id="scenario-3",
                source_behavior="scenario_3",
                scenario_name="sudo_unauthorized_user",
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
            output_path=output_path,
            per_group_limit=10,
            seed=42,
        )
    )

    assert calls == [
        ("cic2017", "a.csv"),
        ("cic2017", "b.csv"),
        ("cic2018", "c.csv"),
        ("adfa", "adfa"),
        ("cmu", "r4.2.tar.bz2"),
    ]

    assert captured["records"] == [
        "2017:a.csv",
        "2017:b.csv",
        "2018:c.csv",
        "adfa-record",
        "cmu-record",
    ]
    assert captured["per_group_limit"] == 10
    assert captured["seed"] == 42

    assert len(manifest) == 2

    written = [
        json.loads(line)
        for line in output_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert written == [
        {
            "label": "benign",
            "source_dataset": "cic_ids_2017",
            "source_row_id": "a.csv:1",
            "source_behavior": "BENIGN",
            "scenario_name": "ssh_authentication_success",
        },
        {
            "label": "privilege_misuse",
            "source_dataset": "cmu_insider",
            "source_row_id": "scenario-3",
            "source_behavior": "scenario_3",
            "scenario_name": "sudo_unauthorized_user",
        },
    ]