import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

MODEL_DIR = Path("models")
ANOMALY_MODEL_PATH = MODEL_DIR / "anomaly.joblib"
CLASSIFIER_MODEL_PATH = MODEL_DIR / "classifier.joblib"
LABEL_MANIFEST_PATH = MODEL_DIR / "label_manifest.json"

LABEL_ORDER = ["Normal", "PortScan", "BruteForce", "LateralMovement", "DataExfiltration"]

FEATURE_COLUMNS = [
    "event_count", "unique_dest_ips", "unique_dest_ports",
    "failed_logins", "success_fail_ratio", "bytes_out", "bytes_in",
    "bytes_per_conn", "new_peer_ratio", "protocol_entropy", "rate_vs_baseline",
]


def _extract_features(feature_vector) -> np.ndarray:
    d = feature_vector.to_dict() if hasattr(feature_vector, "to_dict") else feature_vector
    return np.array([[d[col] for col in FEATURE_COLUMNS]], dtype=np.float64)


def train_anomaly_model(normal_features: np.ndarray) -> IsolationForest:
    model = IsolationForest(random_state=42, contamination=0.05)
    model.fit(normal_features)
    return model


def train_classifier(labeled_features: np.ndarray, labels: list) -> RandomForestClassifier:
    model = RandomForestClassifier(random_state=42, class_weight="balanced")
    model.fit(labeled_features, labels)
    return model


def save_models(anomaly_model, classifier_model):
    import joblib
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(anomaly_model, ANOMALY_MODEL_PATH)
    joblib.dump(classifier_model, CLASSIFIER_MODEL_PATH)

    import json
    with open(LABEL_MANIFEST_PATH, "w") as f:
        json.dump({"label_order": LABEL_ORDER}, f)


def load_models():
    import joblib
    anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
    classifier_model = joblib.load(CLASSIFIER_MODEL_PATH)
    return anomaly_model, classifier_model


def score_windows(feature_vectors, anomaly_model, classifier_model) -> list[dict]:
    """Score a bounded batch of windows; model outputs remain deterministic."""
    if not feature_vectors:
        return []
    rows = [_extract_features(vector)[0] for vector in feature_vectors]
    matrix = np.asarray(rows, dtype=np.float64)
    finite = np.isfinite(matrix).all(axis=1)
    results = [{
        "anomaly_score": 0.0,
        "class_probs": {label: 0.0 for label in LABEL_ORDER},
        "predicted_class": "Normal",
    } for _ in feature_vectors]
    if not finite.any():
        return results

    valid = matrix[finite]
    raw_scores = anomaly_model.score_samples(valid)
    anomaly_scores = np.clip(1.0 - (raw_scores + 0.5), 0.0, 1.0)
    probabilities = classifier_model.predict_proba(valid)
    classes = list(classifier_model.classes_)
    valid_result_index = 0
    for index, is_finite in enumerate(finite):
        if not is_finite:
            continue
        probs = probabilities[valid_result_index]
        result_probs = {label: float(probs[i]) for i, label in enumerate(classes)}
        predicted = classes[int(np.argmax(probs))]
        results[index] = {
            "anomaly_score": float(anomaly_scores[valid_result_index]),
            "class_probs": result_probs,
            "predicted_class": predicted,
        }
        valid_result_index += 1
    return results


def score_window(feature_vector, anomaly_model, classifier_model) -> dict:
    """Compatibility wrapper for scoring one feature vector."""
    return score_windows([feature_vector], anomaly_model, classifier_model)[0]
