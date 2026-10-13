from training.data_contract import (
    TrainingRow,
    training_feature_vector,
)


def deduplicate_rows(
    rows: list[TrainingRow],
) -> tuple[list[TrainingRow], int]:
    seen: set[tuple[object, ...]] = set()
    deduplicated: list[TrainingRow] = []

    for row in rows:
        key = (
            *training_feature_vector(row),
            row.label,
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        deduplicated.append(
            row
        )

    duplicate_count = (
        len(rows)
        - len(deduplicated)
    )

    return (
        deduplicated,
        duplicate_count,
    )