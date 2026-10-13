import pickle

import numpy as np

from app.ml.xgboost_classifier import (
    AthenaSecXGBClassifier,
)


def _fixture_data():
    X = np.asarray(
        [
            [0.0, 0.0],
            [0.1, 0.1],
            [0.2, 0.2],
            [1.0, 1.0],
            [1.1, 1.1],
            [1.2, 1.2],
            [2.0, 2.0],
            [2.1, 2.1],
            [2.2, 2.2],
        ],
        dtype=float,
    )

    y = np.asarray(
        [
            "benign",
            "benign",
            "benign",
            "brute_force",
            "brute_force",
            "brute_force",
            "privilege_misuse",
            "privilege_misuse",
            "privilege_misuse",
        ],
        dtype=object,
    )

    return X, y


def test_xgboost_classifier_preserves_athenasec_string_labels():
    X, y = _fixture_data()

    model = AthenaSecXGBClassifier(
        class_weight={
            "benign": 1.0,
            "brute_force": 2.0,
            "privilege_misuse": 3.0,
        },
        n_estimators=10,
        random_state=42,
        n_jobs=1,
    )

    model.fit(
        X,
        y,
    )

    assert list(
        model.classes_
    ) == [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    predictions = model.predict(
        X
    )

    assert set(
        predictions
    ).issubset(
        {
            "benign",
            "brute_force",
            "privilege_misuse",
        }
    )


def test_xgboost_classifier_probability_contract():
    X, y = _fixture_data()

    model = AthenaSecXGBClassifier(
        class_weight={
            "benign": 1.0,
            "brute_force": 1.0,
            "privilege_misuse": 1.0,
        },
        n_estimators=10,
        random_state=42,
        n_jobs=1,
    )

    model.fit(
        X,
        y,
    )

    probabilities = model.predict_proba(
        X
    )

    assert probabilities.shape == (
        len(X),
        3,
    )

    assert np.allclose(
        probabilities.sum(axis=1),
        1.0,
    )


def test_xgboost_classifier_is_pickle_compatible():
    X, y = _fixture_data()

    model = AthenaSecXGBClassifier(
        class_weight={
            "benign": 1.0,
            "brute_force": 1.0,
            "privilege_misuse": 1.0,
        },
        n_estimators=10,
        random_state=42,
        n_jobs=1,
    )

    model.fit(
        X,
        y,
    )

    restored = pickle.loads(
        pickle.dumps(
            model
        )
    )

    assert list(
        restored.classes_
    ) == [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    assert restored.predict(
        X
    ).tolist() == model.predict(
        X
    ).tolist()
