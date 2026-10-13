import pickle
import re
from pathlib import Path
from typing import Any

from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
)
from app.ml.runtime_classifier import (
    RuntimeMLClassifier,
)


SUPPORTED_ATTACK_CLASSES = {
    "benign",
    "brute_force",
    "privilege_escalation",
    "privilege_misuse",
    "unknown",
}

REQUIRED_ATTACK_CLASSES = {
    "benign",
    "brute_force",
    "privilege_misuse",
}


def _load_artifact(
    artifact_path: str | Path,
) -> dict[str, Any]:
    path = Path(
        artifact_path
    )

    if not path.exists():
        raise FileNotFoundError(
            f"ML model artifact was not found: {path}"
        )

    with path.open(
        "rb"
    ) as file:
        artifact = pickle.load(
            file
        )

    if not isinstance(
        artifact,
        dict,
    ):
        raise ValueError(
            "ML model artifact must be a dictionary."
        )

    return artifact


def _validate_model_interface(
    model: Any,
) -> None:
    predict = getattr(
        model,
        "predict",
        None,
    )

    if not callable(
        predict
    ):
        raise ValueError(
            "ML model must provide a callable "
            "predict method."
        )

    predict_proba = getattr(
        model,
        "predict_proba",
        None,
    )

    if not callable(
        predict_proba
    ):
        raise ValueError(
            "ML model must provide a callable "
            "predict_proba method."
        )

    if not hasattr(
        model,
        "classes_",
    ):
        raise ValueError(
            "ML model must provide classes_."
        )


def _validate_attack_classes(
    model: Any,
) -> None:
    classes = list(
        model.classes_
    )

    unsupported = [
        attack_class
        for attack_class in classes
        if (
            attack_class
            not in SUPPORTED_ATTACK_CLASSES
        )
    ]

    if unsupported:
        joined = ", ".join(
            str(
                attack_class
            )
            for attack_class in unsupported
        )

        raise ValueError(
            "ML model contains unsupported "
            f"attack class: {joined}"
        )

    missing_required = sorted(
        REQUIRED_ATTACK_CLASSES
        - set(classes)
    )

    if missing_required:
        joined = ", ".join(
            missing_required
        )

        raise ValueError(
            "ML model is missing required attack class: "
            f"{joined}"
        )


def load_runtime_classifier(
    artifact_path: str | Path,
) -> RuntimeMLClassifier:
    artifact = _load_artifact(
        artifact_path
    )

    if "model" not in artifact:
        raise ValueError(
            "ML model artifact is missing model."
        )

    if "model_version" not in artifact:
        raise ValueError(
            "ML model artifact is missing model_version."
        )

    if "feature_names" not in artifact:
        raise ValueError(
            "ML model artifact is missing feature_names."
        )

    feature_names = artifact[
        "feature_names"
    ]

    if list(
        feature_names
    ) != ML_FEATURE_NAMES:
        raise ValueError(
            "ML model feature contract does not "
            "match AthenaSec runtime features."
        )

    model_version = artifact[
        "model_version"
    ]

    if (
        not isinstance(
            model_version,
            str,
        )
        or not model_version.strip()
    ):
        raise ValueError(
            "ML model artifact has an invalid "
            "model_version."
        )

    if re.fullmatch(
        r"athenasec-classifier-v[1-9][0-9]*",
        model_version,
    ) is None:
        raise ValueError(
            "ML model artifact has an invalid "
            "model_version format."
        )

    model = artifact[
        "model"
    ]

    _validate_model_interface(
        model
    )

    _validate_attack_classes(
        model
    )

    return RuntimeMLClassifier(
        model=model,
        model_version=model_version,
    )