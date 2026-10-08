import uuid
from typing import Optional


def risk_score(anomaly_score: float, class_probs: dict, zscores: dict, config: dict) -> int:
    weights = config.get("risk_weights", {"anomaly": 0.40, "threat": 0.40, "evidence": 0.20})

    max_class_prob = max(class_probs.values()) if class_probs else 0.0

    strong_features = sum(1 for z in zscores.values() if abs(z) >= 3.0)
    boost = min(1.0, strong_features / 3.0)

    raw = 100 * (
        weights["anomaly"] * anomaly_score
        + weights["threat"] * max_class_prob
        + weights["evidence"] * boost
    )

    return max(0, min(100, round(raw)))


def get_band(score: int, config: dict) -> str:
    bands = config.get("risk_bands", {})
    normal_max = bands.get("normal", [0, 30])[1]
    suspicious_max = bands.get("suspicious", [31, 70])[1]

    if score <= normal_max:
        return "Normal"
    elif score <= suspicious_max:
        return "Suspicious"
    else:
        return "Malicious"


def build_evidence(feature_vector, zscores: dict, class_probs: dict, top_n: int = 5) -> list:
    d = feature_vector.to_dict() if hasattr(feature_vector, "to_dict") else feature_vector

    evidence = []
    for feature_name, value in d.items():
        if feature_name in ("source_ip", "window_start", "window_end", "record_ids"):
            continue
        if not isinstance(value, (int, float)):
            continue

        zscore = zscores.get(feature_name, 0.0)
        importance = abs(zscore)

        evidence.append({
            "feature": feature_name,
            "value": value,
            "zscore": round(zscore, 2),
            "contribution": round(importance, 4),
        })

    evidence.sort(key=lambda e: e["contribution"], reverse=True)
    return evidence[:top_n]


def build_alert(
    feature_vector,
    anomaly_score: float,
    class_probs: dict,
    predicted_class: str,
    zscores: dict,
    evidence: list,
    model_version: str = "anomaly-if-v1 / clf-rf-v1",
    config: dict = None,
) -> dict:
    if config is None:
        config = {}

    d = feature_vector.to_dict() if hasattr(feature_vector, "to_dict") else feature_vector

    score = risk_score(anomaly_score, class_probs, zscores, config)
    band = get_band(score, config)

    alert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{d['source_ip']}:{d['window_start']}"))

    return {
        "alert_id": alert_id,
        "timestamp": d["window_start"],
        "source_ip": d["source_ip"],
        "dest_ip": d.get("dest_ip", ""),
        "classification": band,
        "threat_category": predicted_class,
        "risk_score": score,
        "evidence": evidence,
        "anomaly_score": round(anomaly_score, 4),
        "class_probabilities": class_probs,
        "model_version": model_version,
        "record_ids": d.get("record_ids", []),
        "status": "new",
    }
