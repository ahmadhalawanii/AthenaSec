import pickle
from pathlib import Path
from typing import Any

from training.data_contract import (
    training_feature_names,
)


def export_model_artifact(
    model: Any,
    artifact_path: str | Path,
    model_version: str,
) -> None:
    path = Path(
        artifact_path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact = {
        "model": model,
        "model_version": model_version,
        "feature_names": (
            training_feature_names()
        ),
    }

    with path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )