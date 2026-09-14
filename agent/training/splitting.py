from dataclasses import dataclass

from sklearn.model_selection import (
    train_test_split,
)

from training.data_contract import (
    TrainingRow,
)


@dataclass(frozen=True)
class DatasetSplit:
    train: list[TrainingRow]
    validation: list[TrainingRow]
    test: list[TrainingRow]


def split_rows(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> DatasetSplit:
    if not rows:
        raise ValueError(
            "Training rows must not be empty."
        )

    grouped_rows: dict[
        tuple[str, str],
        list[TrainingRow],
    ] = {}

    for row in rows:
        group_key = (
            row.source_dataset,
            row.source_row_id,
        )

        grouped_rows.setdefault(
            group_key,
            [],
        ).append(row)

    group_labels: dict[
        tuple[str, str],
        str,
    ] = {}

    for group_key, group in (
        grouped_rows.items()
    ):
        labels = {
            row.label
            for row in group
        }

        if len(labels) != 1:
            raise ValueError(
                "Rows sharing the same "
                "provenance group must have "
                "the same label."
            )

        group_labels[group_key] = (
            next(iter(labels))
        )

    group_keys = list(
        grouped_rows
    )

    try:
        (
            train_group_keys,
            temporary_group_keys,
        ) = train_test_split(
            group_keys,
            test_size=0.30,
            random_state=random_state,
            stratify=[
                group_labels[group_key]
                for group_key in group_keys
            ],
        )

        (
            validation_group_keys,
            test_group_keys,
        ) = train_test_split(
            temporary_group_keys,
            test_size=0.50,
            random_state=random_state,
            stratify=[
                group_labels[group_key]
                for group_key
                in temporary_group_keys
            ],
        )

    except ValueError as exc:
        raise ValueError(
            "Unable to create a stratified "
            "70/15/15 split. Each class must "
            "contain enough independent "
            "provenance groups."
        ) from exc

    train_rows = [
        row
        for group_key
        in train_group_keys
        for row
        in grouped_rows[group_key]
    ]

    validation_rows = [
        row
        for group_key
        in validation_group_keys
        for row
        in grouped_rows[group_key]
    ]

    test_rows = [
        row
        for group_key
        in test_group_keys
        for row
        in grouped_rows[group_key]
    ]

    return DatasetSplit(
        train=train_rows,
        validation=validation_rows,
        test=test_rows,
    )


def leave_one_dataset_out(
    rows: list[TrainingRow],
    held_out_dataset: str,
) -> tuple[
    list[TrainingRow],
    list[TrainingRow],
]:
    training_rows = [
        row
        for row in rows
        if (
            row.source_dataset
            != held_out_dataset
        )
    ]

    held_out_rows = [
        row
        for row in rows
        if (
            row.source_dataset
            == held_out_dataset
        )
    ]

    return (
        training_rows,
        held_out_rows,
    )