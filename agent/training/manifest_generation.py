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
from training.behavior_manifest import (
    BehaviorReplay,
    build_behavior_manifest,
)


def generate_behavior_replay_manifest(
    *,
    cic2017_dir: str | Path,
    cic2018_dir: str | Path,
    adfa_root: str | Path,
    cmu_archive: str | Path,
    output_path: str | Path,
    per_group_limit: int,
    seed: int,
) -> list[BehaviorReplay]:
    records = []

    for csv_path in sorted(
        Path(cic2017_dir).rglob("*.csv")
    ):
        records.extend(
            iter_cic2017_records(csv_path)
        )

    for csv_path in sorted(
        Path(cic2018_dir).rglob("*.csv")
    ):
        records.extend(
            iter_cic2018_records(csv_path)
        )

    records.extend(
        iter_adfa_records(adfa_root)
    )

    records.extend(
        iter_cmu_scenarios(cmu_archive)
    )

    manifest = build_behavior_manifest(
        records,
        per_group_limit=per_group_limit,
        seed=seed,
    )

    destination = Path(output_path)
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
                    dataclasses.asdict(replay),
                    separators=(",", ":"),
                )
            )
            handle.write("\n")

    return manifest