import pickle

import pytest

from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
)
from app.ml.model_loader import (
    load_runtime_classifier,
)


class FakeModel:
    classes_ = [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.05,
                0.90,
                0.05,
            ]
        ]


def test_model_loader_builds_runtime_classifier(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "athenasec-model.pkl"
    )

    artifact = {
        "model": FakeModel(),
        "model_version": (
            "athenasec-classifier-v1"
        ),
        "feature_names": (
            ML_FEATURE_NAMES
        ),
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    classifier = load_runtime_classifier(
        artifact_path
    )

    assert (
        classifier.model_version
        == "athenasec-classifier-v1"
    )


def test_model_loader_rejects_wrong_feature_contract(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "athenasec-bad-model.pkl"
    )

    artifact = {
        "model": FakeModel(),
        "model_version": (
            "athenasec-classifier-v1"
        ),
        "feature_names": [
            "wrong_feature",
        ],
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="feature contract",
    ):
        load_runtime_classifier(
            artifact_path
        )


class MissingPredictModel:
    classes_ = [
        "benign",
        "brute_force",
    ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.2,
                0.8,
            ]
        ]


def test_model_loader_rejects_model_without_predict(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "missing-predict.pkl"
    )

    artifact = {
        "model": MissingPredictModel(),
        "model_version": (
            "athenasec-classifier-v1"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="predict",
    ):
        load_runtime_classifier(
            artifact_path
        )


class MissingProbabilityModel:
    classes_ = [
        "benign",
        "brute_force",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]


def test_model_loader_rejects_model_without_predict_proba(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "missing-proba.pkl"
    )

    artifact = {
        "model": MissingProbabilityModel(),
        "model_version": (
            "athenasec-classifier-v2"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="predict_proba",
    ):
        load_runtime_classifier(
            artifact_path
        )


class MissingClassesModel:
    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.2,
                0.8,
            ]
        ]


def test_model_loader_rejects_model_without_classes(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "missing-classes.pkl"
    )

    artifact = {
        "model": MissingClassesModel(),
        "model_version": (
            "athenasec-classifier-v3"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="classes_",
    ):
        load_runtime_classifier(
            artifact_path
        )


class UnsupportedClassModel:
    classes_ = [
        "benign",
        "brute_force",
        "ransomware",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.1,
                0.8,
                0.1,
            ]
        ]


def test_model_loader_rejects_unsupported_attack_class(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "unsupported-class.pkl"
    )

    artifact = {
        "model": UnsupportedClassModel(),
        "model_version": (
            "athenasec-classifier-v4"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="unsupported attack class",
    ):
        load_runtime_classifier(
            artifact_path
        )


def test_model_loader_rejects_empty_model_version(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "empty-version.pkl"
    )

    artifact = {
        "model": FakeModel(),
        "model_version": "",
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="model_version",
    ):
        load_runtime_classifier(
            artifact_path
        )


def test_model_loader_rejects_invalid_model_version_format(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "invalid-version.pkl"
    )

    artifact = {
        "model": FakeModel(),
        "model_version": (
            "random-model-name"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="model_version",
    ):
        load_runtime_classifier(
            artifact_path
        )

class MissingRequiredClassModel:
    classes_ = [
        "benign",
        "brute_force",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.1,
                0.9,
            ]
        ]

def test_model_loader_rejects_missing_required_attack_class(
    tmp_path,
):
    artifact_path = (
        tmp_path
        / "missing-required-class.pkl"
    )

    artifact = {
        "model": MissingRequiredClassModel(),
        "model_version": (
            "athenasec-classifier-v1"
        ),
        "feature_names": ML_FEATURE_NAMES,
    }

    with artifact_path.open(
        "wb"
    ) as file:
        pickle.dump(
            artifact,
            file,
        )

    with pytest.raises(
        ValueError,
        match="required attack class",
    ):
        load_runtime_classifier(
            artifact_path
        )