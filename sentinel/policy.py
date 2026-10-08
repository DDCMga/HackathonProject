"""Deterministic policy checks for Sentinel alerts."""


def is_breach(alert: dict, max_risk: int) -> bool:
    return int(alert["risk_score"]) > max_risk


def find_breach(alerts, max_risk: int):
    for alert in alerts:
        if is_breach(alert, max_risk):
            return alert
    return None


def policy_exit_code(alerts, max_risk: int) -> int:
    return int(find_breach(alerts, max_risk) is not None)
