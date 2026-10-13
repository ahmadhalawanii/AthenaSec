from collections import Counter
from typing import Sequence

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

from training.data_contract import (
    TRAINING_LABELS,
    TrainingRow,
)


_LABEL_ORDER = list(
    TRAINING_LABELS
)


def evaluate_predictions(
    y_true: Sequence[str],
    y_pred: Sequence[str],
) -> dict[str, object]:
    precision, recall, f1, support = (
        precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=_LABEL_ORDER,
            zero_division=0,
        )
    )

    per_class = {
        label: {
            "precision": float(
                precision[index]
            ),
            "recall": float(
                recall[index]
            ),
            "f1": float(
                f1[index]
            ),
            "support": int(
                support[index]
            ),
        }
        for index, label in enumerate(
            _LABEL_ORDER
        )
    }

    support_counts = Counter(
        y_true
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=_LABEL_ORDER,
    )

    return {
        "accuracy": float(
            accuracy_score(
                y_true,
                y_pred,
            )
        ),
        "macro_precision": float(
            precision.mean()
        ),
        "macro_recall": float(
            recall.mean()
        ),
        "macro_f1": float(
            f1.mean()
        ),
        "per_class": per_class,
        "confusion_matrix": (
            matrix.tolist()
        ),
        "support": {
            label: int(
                support_counts.get(
                    label,
                    0,
                )
            )
            for label in _LABEL_ORDER
        },
    }


def evaluate_by_dataset(
    rows: list[TrainingRow],
    y_pred: Sequence[str],
) -> dict[
    str,
    dict[str, object],
]:
    if len(
        rows
    ) != len(
        y_pred
    ):
        raise ValueError(
            "rows and y_pred must "
            "have the same length."
        )

    grouped_true: dict[
        str,
        list[str],
    ] = {}

    grouped_pred: dict[
        str,
        list[str],
    ] = {}

    for row, prediction in zip(
        rows,
        y_pred,
        strict=True,
    ):
        grouped_true.setdefault(
            row.source_dataset,
            [],
        ).append(
            row.label
        )

        grouped_pred.setdefault(
            row.source_dataset,
            [],
        ).append(
            prediction
        )

    return {
        dataset: evaluate_predictions(
            grouped_true[dataset],
            grouped_pred[dataset],
        )
        for dataset in grouped_true
    }