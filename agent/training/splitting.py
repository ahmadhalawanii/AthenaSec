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


def _labels(
    rows: list[TrainingRow],
) -> list[str]:
    return [
        row.label
        for row in rows
    ]


def split_rows(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> DatasetSplit:
    if not rows:
        raise ValueError(
            "Training rows must not be empty."
        )

    try:
        train_rows, temporary_rows = (
            train_test_split(
                rows,
                test_size=0.30,
                random_state=random_state,
                stratify=_labels(
                    rows
                ),
            )
        )

        validation_rows, test_rows = (
            train_test_split(
                temporary_rows,
                test_size=0.50,
                random_state=random_state,
                stratify=_labels(
                    temporary_rows
                ),
            )
        )

    except ValueError as exc:
        raise ValueError(
            "Unable to create a stratified "
            "70/15/15 split. Each class must "
            "contain enough samples."
        ) from exc

    return DatasetSplit(
        train=list(
            train_rows
        ),
        validation=list(
            validation_rows
        ),
        test=list(
            test_rows
        ),
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