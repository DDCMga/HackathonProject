import numpy as np

from sentinel.models import FEATURE_COLUMNS, score_window, train_anomaly_model, train_classifier


def test_models_are_repeatable_and_scores_are_bounded():
    rng = np.random.default_rng(42)
    normal = rng.normal(size=(40, len(FEATURE_COLUMNS)))
    labels = ["Normal"] * 20 + ["PortScan"] * 20
    values = np.vstack([normal[:20], normal[20:] + 3])
    first_anomaly = train_anomaly_model(normal[:20])
    second_anomaly = train_anomaly_model(normal[:20])
    first_classifier = train_classifier(values, labels)
    second_classifier = train_classifier(values, labels)

    class Vector:
        def to_dict(self):
            return dict(zip(FEATURE_COLUMNS, values[22]))

    a = score_window(Vector(), first_anomaly, first_classifier)
    b = score_window(Vector(), second_anomaly, second_classifier)
    assert a == b
    assert 0.0 <= a["anomaly_score"] <= 1.0
    assert abs(sum(a["class_probs"].values()) - 1.0) < 1e-9


def test_nonfinite_feature_vector_is_not_scored():
    class Vector:
        def to_dict(self):
            return {name: float("nan") for name in FEATURE_COLUMNS}

    class ExplodingModel:
        def score_samples(self, _):
            raise AssertionError("nonfinite input reached model")

    result = score_window(Vector(), ExplodingModel(), ExplodingModel())
    assert result["predicted_class"] == "Normal"
    assert result["anomaly_score"] == 0.0
