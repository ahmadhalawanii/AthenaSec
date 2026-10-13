import pickle

import pytest

from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
)
from app.ml.runtime_classifier import (
    RuntimeMLClassifier,
)
from app.ml.runtime_config import (
    build_ml_classifier_from_env,
)


class FakeProductionModel:
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


def test_build_ml_classifier_from_env_loads_configured_model(
    tmp_path,
    monkeypatch,
):
    artifact_path = (
        tmp_path
        / "athenasec-classifier.pkl"
    )

    artifact = {
        "model": FakeProductionModel(),
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

    monkeypatch.setenv(
        "ATHENASEC_ML_MODEL_PATH",
        str(
            artifact_path
        ),
    )

    classifier = (
        build_ml_classifier_from_env()
    )

    assert isinstance(
        classifier,
        RuntimeMLClassifier,
    )

    assert (
        classifier.model_version
        == "athenasec-classifier-v1"
    )


def test_build_ml_classifier_from_env_fails_when_path_missing(
    monkeypatch,
):
    monkeypatch.delenv(
        "ATHENASEC_ML_MODEL_PATH",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="ATHENASEC_ML_MODEL_PATH",
    ):
        build_ml_classifier_from_env()

from app.ml.runtime_config import (
    UnavailableMLClassifier,
)


def test_unavailable_ml_classifier_fails_explicitly():
    classifier = UnavailableMLClassifier(
        reason=(
            "ATHENASEC_ML_MODEL_PATH "
            "is not configured."
        )
    )

    with pytest.raises(
        RuntimeError,
        match="ATHENASEC_ML_MODEL_PATH",
    ):
        classifier.classify(
            None
        )

from app.ml.runtime_config import (
    build_live_ml_classifier,
)


def test_build_live_ml_classifier_returns_real_classifier_when_configured(
    tmp_path,
    monkeypatch,
):
    artifact_path = (
        tmp_path
        / "athenasec-live-classifier.pkl"
    )

    artifact = {
        "model": FakeProductionModel(),
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

    monkeypatch.setenv(
        "ATHENASEC_ML_MODEL_PATH",
        str(
            artifact_path
        ),
    )

    classifier = (
        build_live_ml_classifier()
    )

    assert isinstance(
        classifier,
        RuntimeMLClassifier,
    )


def test_build_live_ml_classifier_returns_unavailable_classifier_on_failure(
    monkeypatch,
):
    monkeypatch.delenv(
        "ATHENASEC_ML_MODEL_PATH",
        raising=False,
    )

    classifier = (
        build_live_ml_classifier()
    )

    assert isinstance(
        classifier,
        UnavailableMLClassifier,
    )

    with pytest.raises(
        RuntimeError,
        match="ATHENASEC_ML_MODEL_PATH",
    ):
        classifier.classify(
            None
        )