import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_X_IIOTID_LABEL_MAP = {
    "Normal": "benign",
    "BruteForce": "brute_force",
    "Dictionary": "brute_force",
    "insider_malcious": "privilege_misuse",
}


@dataclass(frozen=True)
class XIIoTIDRecord:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, str]


def map_x_iiotid_label(
    raw_label: str,
) -> str | None:
    normalized = raw_label.strip()

    return _X_IIOTID_LABEL_MAP.get(
        normalized
    )


def iter_x_iiotid_records(
    csv_path: str | Path,
) -> Iterator[XIIoTIDRecord]:
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
                "class1",
                "",
            )

            label = map_x_iiotid_label(
                raw_label
            )

            if label is None:
                continue

            yield XIIoTIDRecord(
                label=label,
                source_dataset="x_iiotid",
                source_row_id=(
                    f"{path.name}:{row_number}"
                ),
                raw_label=raw_label,
                fields=dict(fields),
            )