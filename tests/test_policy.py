from sentinel.policy import find_breach, is_breach, policy_exit_code


def test_threshold_is_strictly_exceeded():
    alerts = [{"risk_score": 70}, {"risk_score": 71}]
    assert not is_breach(alerts[0], 70)
    assert is_breach(alerts[1], 70)
    assert find_breach(alerts, 70) is alerts[1]
    assert policy_exit_code(alerts[:1], 70) == 0
    assert policy_exit_code(alerts, 70) == 1
