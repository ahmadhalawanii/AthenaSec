import csv
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class CMUInsiderScenario:
    label: str
    source_dataset: str
    source_row_id: str
    source_file: str
    dataset: str
    scenario: int
    insider_user: str
    start: str
    end: str
    events: tuple[
        tuple[str, ...],
        ...,
    ]


def map_cmu_scenario(
    dataset: str,
    scenario: int | str,
) -> str | None:
    normalized_dataset = dataset.strip()

    try:
        normalized_scenario = int(
            scenario
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if (
        normalized_dataset == "4.2"
        and normalized_scenario == 3
    ):
        return "privilege_misuse"

    return None


def _read_csv_member(
    archive: tarfile.TarFile,
    member_name: str,
) -> list[list[str]]:
    extracted = archive.extractfile(
        member_name
    )

    if extracted is None:
        raise RuntimeError(
            f"Could not read archive member: "
            f"{member_name}"
        )

    text = extracted.read().decode(
        "utf-8-sig",
        errors="replace",
    )

    return list(
        csv.reader(
            io.StringIO(text)
        )
    )


def iter_cmu_scenarios(
    archive_path: str | Path,
) -> Iterator[CMUInsiderScenario]:
    path = Path(archive_path)

    with tarfile.open(
        path,
        mode="r:bz2",
    ) as archive:
        insiders_file = (
            archive.extractfile(
                "answers/insiders.csv"
            )
        )

        if insiders_file is None:
            raise RuntimeError(
                "Could not read "
                "answers/insiders.csv"
            )

        insiders_text = (
            insiders_file
            .read()
            .decode(
                "utf-8-sig",
                errors="replace",
            )
        )

        insiders = csv.DictReader(
            io.StringIO(
                insiders_text
            )
        )

        for insider in insiders:
            dataset = (
                insider
                .get(
                    "dataset",
                    "",
                )
                .strip()
            )

            scenario_raw = (
                insider
                .get(
                    "scenario",
                    "",
                )
                .strip()
            )

            label = map_cmu_scenario(
                dataset=dataset,
                scenario=scenario_raw,
            )

            if label is None:
                continue

            scenario = int(
                scenario_raw
            )

            details = (
                insider
                .get(
                    "details",
                    "",
                )
                .strip()
            )

            insider_user = (
                insider
                .get(
                    "user",
                    "",
                )
                .strip()
            )

            start = (
                insider
                .get(
                    "start",
                    "",
                )
                .strip()
            )

            end = (
                insider
                .get(
                    "end",
                    "",
                )
                .strip()
            )

            source_file = (
                f"answers/"
                f"r{dataset}-{scenario}/"
                f"{details}"
            )

            rows = _read_csv_member(
                archive,
                source_file,
            )

            events = tuple(
                tuple(row)
                for row in rows
            )

            yield CMUInsiderScenario(
                label=label,
                source_dataset=(
                    "cmu_cert_r4_2"
                ),
                source_row_id=(
                    source_file
                ),
                source_file=(
                    source_file
                ),
                dataset=dataset,
                scenario=scenario,
                insider_user=(
                    insider_user
                ),
                start=start,
                end=end,
                events=events,
            )