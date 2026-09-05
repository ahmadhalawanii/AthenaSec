from pathlib import Path

from sklearn.ensemble import (
    RandomForestClassifier,
)

from app.ml.model_loader import (
    load_runtime_classifier,
)
from training.artifact_export import (
    export_model_artifact,
)
from training.data_contract import (
    training_feature_names,
)


def _trained_model() -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=5,
        random_state=42,
    )

    X = [
        [0.0] * 11,
        [1.0] * 11,
        [2.0] * 11,
    ]

    y = [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    model.fit(
        X,
        y,
    )

    return model


def test_exported_artifact_loads_with_runtime_loader(
    tmp_path: Path,
):
    model = _trained_model()

    artifact_path = (
        tmp_path
        / "classifier.pkl"
    )

    export_model_artifact(
        model=model,
        artifact_path=artifact_path,
        model_version=(
            "athenasec-classifier-v1"
        ),
    )

    classifier = (
        load_runtime_classifier(
            artifact_path
        )
    )

    assert (
        classifier.model_version
        == "athenasec-classifier-v1"
    )

    assert list(
        classifier.model.classes_
    ) == [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]


def test_export_uses_runtime_feature_contract(
    tmp_path: Path,
):
    import pickle

    model = _trained_model()

    artifact_path = (
        tmp_path
        / "classifier.pkl"
    )

    export_model_artifact(
        model=model,
        artifact_path=artifact_path,
        model_version=(
            "athenasec-classifier-v1"
        ),
    )

    with artifact_path.open(
        "rb"
    ) as file:
        artifact = pickle.load(
            file
        )

    assert artifact[
        "feature_names"
    ] == training_feature_names()