import random
from collections import Counter

from training.data_contract import (
    TRAINING_LABELS,
    TrainingRow,
)


def class_weight_map(
    rows: list[TrainingRow],
) -> dict[str, float]:
    if not rows:
        raise ValueError(
            "Training rows must not be empty."
        )

    counts = Counter(
        row.label
        for row in rows
    )

    missing_labels = [
        label
        for label in TRAINING_LABELS
        if counts[label] == 0
    ]

    if missing_labels:
        raise ValueError(
            "All training classes must be "
            "present to calculate class weights."
        )

    total = len(
        rows
    )

    class_count = len(
        TRAINING_LABELS
    )

    return {
        label: (
            total
            / (
                class_count
                * counts[label]
            )
        )
        for label in TRAINING_LABELS
    }


def undersample_benign(
    rows: list[TrainingRow],
    max_ratio: float = 3.0,
    random_state: int = 42,
) -> list[TrainingRow]:
    if max_ratio <= 0:
        raise ValueError(
            "max_ratio must be greater than 0."
        )

    benign_rows = [
        row
        for row in rows
        if row.label == "benign"
    ]

    attack_rows = [
        row
        for row in rows
        if row.label != "benign"
    ]

    attack_counts = Counter(
        row.label
        for row in attack_rows
    )

    largest_attack_class = max(
        attack_counts.values(),
        default=0,
    )

    if largest_attack_class == 0:
        return rows

    maximum_benign_count = int(
        largest_attack_class
        * max_ratio
    )

    if (
        len(benign_rows)
        <= maximum_benign_count
    ):
        return rows

    random_generator = random.Random(
        random_state
    )

    selected_benign_rows = (
        random_generator.sample(
            benign_rows,
            maximum_benign_count,
        )
    )

    selected_ids = {
        id(row)
        for row in selected_benign_rows
    }

    balanced_rows = [
        row
        for row in rows
        if (
            row.label != "benign"
            or id(row) in selected_ids
        )
    ]

    return balanced_rows