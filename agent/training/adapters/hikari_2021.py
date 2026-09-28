import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_HIKARI_2021_LABEL_MAP = {
    "Benign": "benign",
    "Bruteforce": "brute_force",
    "Bruteforce-XML": "brute_force",
}


@dataclass(frozen=True)
class HIKARI2021Record:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, str]


def map_hikari_2021_label(
    raw_label: str,
) -> str | None:
    normalized = raw_label.strip()

    return _HIKARI_2021_LABEL_MAP.get(
        normalized
    )


def iter_hikari_2021_records(
    csv_path: str | Path,
) -> Iterator[HIKARI2021Record]:
    path = Path(csv_path)

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames is None:
            return

        reader.fieldnames = [
            field_name.strip()
            for field_name in reader.fieldnames
        ]

        for row_number, fields in enumerate(
            reader,
            start=1,
        ):
            raw_label = fields.get(
                "traffic_category",
                "",
            )

            label = map_hikari_2021_label(
                raw_label
            )

            if label is None:
                continue

            yield HIKARI2021Record(
                label=label,
                source_dataset="hikari_2021",
                source_row_id=(
                    f"{path.name}:{row_number}"
                ),
                raw_label=raw_label,
                fields=dict(fields),
            )