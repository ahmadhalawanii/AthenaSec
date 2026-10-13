from training.deduplication import (
    deduplicate_rows,
)
from training.balancing import (
    class_weight_map,
    undersample_benign,
)
from training.data_contract import (
    TrainingRow,
)
from training.evaluate import (
    evaluate_predictions,
)
from training.preprocessing import (
    build_random_forest,
    build_xy,
)
from training.splitting import (
    leave_one_dataset_out,
)
from training.validation import (
    validate_training_rows,
)


def evaluate_leave_one_dataset_out(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> dict[
    str,
    dict[str, object],
]:
    validate_training_rows(
        rows
    )

    datasets = sorted(
        {
            row.source_dataset
            for row in rows
        }
    )

    results: dict[
        str,
        dict[str, object],
    ] = {}

    for dataset in datasets:
        training_rows, held_out_rows = (
            leave_one_dataset_out(
                rows,
                held_out_dataset=dataset,
            )
        )
        training_rows, _ = (
            deduplicate_rows(
                training_rows
            )
        )

        held_out_rows, _ = (
            deduplicate_rows(
                held_out_rows
            )
        )

        if not training_rows:
            raise ValueError(
                "No training rows remain after "
                f"holding out dataset: {dataset}"
            )

        if not held_out_rows:
            raise ValueError(
                "Held-out dataset contains "
                f"no rows: {dataset}"
            )

        balanced_training_rows = (
            undersample_benign(
                training_rows,
                random_state=random_state,
            )
        )

        class_weights = class_weight_map(
            balanced_training_rows
        )

        train_X, train_y = build_xy(
            balanced_training_rows
        )

        held_out_X, held_out_y = build_xy(
            held_out_rows
        )

        model = build_random_forest(
            class_weight=class_weights,
            random_state=random_state,
        )

        model.fit(
            train_X,
            train_y,
        )

        predictions = model.predict(
            held_out_X
        )

        results[dataset] = (
            evaluate_predictions(
                held_out_y,
                predictions,
            )
        )

    return results