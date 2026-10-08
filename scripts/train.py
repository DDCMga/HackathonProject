import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.features import build_windows
from sentinel.ingest import iter_records, load_config
from sentinel.models import (
    train_anomaly_model, train_classifier, save_models,
    LABEL_ORDER, FEATURE_COLUMNS,
)


LABEL_MAP = {
    "Normal": "Normal",
    "port_scan": "PortScan",
    "brute_force": "BruteForce",
    "lateral_movement": "LateralMovement",
    "data_exfiltration": "DataExfiltration",
}

SEVERITY_ORDER = {
    "Normal": 0,
    "PortScan": 1,
    "BruteForce": 2,
    "LateralMovement": 3,
    "DataExfiltration": 4,
}


def load_training_data(data_dir: str = "data/train"):
    config = load_config()
    events = list(iter_records(f"{data_dir}/train.jsonl", config))

    labeled_records = {}
    with open(f"{data_dir}/labels.jsonl") as f:
        for line in f:
            entry = json.loads(line)
            for rid in entry["record_ids"]:
                labeled_records[rid] = entry["label"]

    windows = list(build_windows(events, config["window_seconds"], config["hop_seconds"]))

    normal_features = []
    labeled_features = []
    labels = []

    for w in windows:
        d = w.to_dict()
        feature_row = [d[col] for col in FEATURE_COLUMNS]

        window_label = "Normal"
        for rid in w.record_ids:
            if rid in labeled_records:
                raw_label = labeled_records[rid]
                candidate = LABEL_MAP.get(raw_label, "Normal")
                if SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(window_label, 0):
                    window_label = candidate

        if window_label == "Normal":
            normal_features.append(feature_row)
        labeled_features.append(feature_row)
        labels.append(window_label)

    return np.array(normal_features), np.array(labeled_features), labels


def main():
    print("Loading training data...")
    normal_features, labeled_features, labels = load_training_data()

    print(f"Normal windows: {len(normal_features)}")
    print(f"Labeled windows: {len(labeled_features)}")

    print("Training IsolationForest...")
    anomaly_model = train_anomaly_model(normal_features)

    print("Training RandomForest classifier...")
    classifier_model = train_classifier(labeled_features, labels)

    save_models(anomaly_model, classifier_model)
    print("Models saved to models/")

    X_train, X_test, y_train, y_test = train_test_split(
        labeled_features, labels, test_size=0.2, random_state=42, stratify=labels
    )

    clf_eval = train_classifier(X_train, y_train)
    y_pred = clf_eval.predict(X_test)

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=LABEL_ORDER)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("\nConfusion Matrix:")
    print(cm)

    metrics = {
        "report": report,
        "confusion_matrix": cm.tolist(),
        "label_order": LABEL_ORDER,
    }
    Path("docs").mkdir(exist_ok=True)
    with open("docs/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("\nMetrics saved to docs/metrics.json")


if __name__ == "__main__":
    main()
