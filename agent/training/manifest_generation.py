import dataclasses
import json
from pathlib import Path

from training.adapters.adfa_ld import (
    iter_adfa_records,
)
from training.adapters.cic_ids_2017 import (
    iter_cic2017_records,
)
from training.adapters.cic_ids_2018 import (
    iter_cic2018_records,
)
from training.adapters.cmu_insider import (
    iter_cmu_scenarios,
)
from training.adapters.ciciot2023 import (
    iter_ciciot2023_records,
)
from training.adapters.hikari_2021 import (
    iter_hikari_2021_records,
)
from training.adapters.lid_ds_2021 import (
    iter_lid_ds_2021_records,
)
from training.adapters.ton_iot import (
    iter_ton_iot_records,
)
from training.adapters.x_iiotid import (
    iter_x_iiotid_records,
)
from training.behavior_manifest import (
    BehaviorReplay,
    build_behavior_manifest,
)


_VALIDATED_TON_IOT_RELATIVE_PATHS = (
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
)


def _iter_ton_iot_records(
    ton_iot_root: str | Path,
):
    root = Path(
        ton_iot_root
    )

    for relative_path in (
        _VALIDATED_TON_IOT_RELATIVE_PATHS
    ):
        csv_path = (
            root
            / Path(relative_path)
        )

        if not csv_path.is_file():
            continue

        yield from iter_ton_iot_records(
            csv_path
        )


def _extend_ton_iot_records(
    records: list,
    ton_iot_root: str | Path,
) -> None:
    records.extend(
        _iter_ton_iot_records(
            ton_iot_root
        )
    )


def _iter_all_behavior_records(
    *,
    cic2017_dir: str | Path,
    cic2018_dir: str | Path,
    adfa_root: str | Path,
    cmu_archive: str | Path,
    ciciot2023_dir: str | Path,
    hikari_dir: str | Path,
    lid_ds_root: str | Path,
    ton_iot_dir: str | Path,
    x_iiotid_csv: str | Path,
):
    for csv_path in sorted(
        Path(cic2017_dir).rglob(
            "*.csv"
        )
    ):
        yield from iter_cic2017_records(
            csv_path
        )

    for csv_path in sorted(
        Path(cic2018_dir).rglob(
            "*.csv"
        )
    ):
        yield from iter_cic2018_records(
            csv_path
        )

    yield from iter_adfa_records(
        adfa_root
    )

    yield from iter_cmu_scenarios(
        cmu_archive
    )

    for csv_path in sorted(
        Path(ciciot2023_dir).rglob(
            "*.csv"
        )
    ):
        yield from iter_ciciot2023_records(
            csv_path
        )

    for csv_path in sorted(
        Path(hikari_dir).rglob(
            "*.csv"
        )
    ):
        yield from iter_hikari_2021_records(
            csv_path
        )

    yield from iter_lid_ds_2021_records(
        lid_ds_root
    )

    yield from _iter_ton_iot_records(
        ton_iot_dir
    )

    yield from iter_x_iiotid_records(
        x_iiotid_csv
    )


def generate_behavior_replay_manifest(
    *,
    cic2017_dir: str | Path,
    cic2018_dir: str | Path,
    adfa_root: str | Path,
    cmu_archive: str | Path,
    ciciot2023_dir: str | Path,
    hikari_dir: str | Path,
    lid_ds_root: str | Path,
    ton_iot_dir: str | Path,
    x_iiotid_csv: str | Path,
    output_path: str | Path,
    per_group_limit: int,
    seed: int,
) -> list[BehaviorReplay]:
    records = _iter_all_behavior_records(
        cic2017_dir=cic2017_dir,
        cic2018_dir=cic2018_dir,
        adfa_root=adfa_root,
        cmu_archive=cmu_archive,
        ciciot2023_dir=ciciot2023_dir,
        hikari_dir=hikari_dir,
        lid_ds_root=lid_ds_root,
        ton_iot_dir=ton_iot_dir,
        x_iiotid_csv=x_iiotid_csv,
    )

    manifest = build_behavior_manifest(
        records,
        per_group_limit=per_group_limit,
        seed=seed,
    )

    destination = Path(
        output_path
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        for replay in manifest:
            handle.write(
                json.dumps(
                    dataclasses.asdict(
                        replay
                    ),
                    separators=(
                        ",",
                        ":",
                    ),
                )
            )
            handle.write("\n")

    return manifest