import json
from pathlib import Path

from training.data_contract import (
    TrainingRow,
)
from training.wazuh_bridge import (
    training_row_from_wazuh_event,
)


def load_labeled_wazuh_events(
    dataset_path: str | Path,
) -> list[TrainingRow]:
    path = Path(
        dataset_path
    )

    rows: list[TrainingRow] = []

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            record = json.loads(
                stripped
            )

            row = training_row_from_wazuh_event(
                event=record["event"],
                label=record["label"],
                source_dataset=(
                    record["source_dataset"]
                ),
                source_row_id=(
                    record["source_row_id"]
                ),
            )

            rows.append(
                row
            )

    return rows