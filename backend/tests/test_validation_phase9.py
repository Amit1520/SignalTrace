from backend.validation.phase9 import run_correlation_scenarios, run_detection_scenarios


def test_phase9_detection_scenarios_are_repeatable_and_pass() -> None:
    first = run_detection_scenarios()
    second = run_detection_scenarios()

    assert first == second
    assert first
    assert all(result.passed for result in first)
    assert any(result.actual_result == "insufficient baseline" for result in first)
    assert any(result.deterministic_signals for result in first)


def test_phase9_correlation_scenarios_cover_positive_and_negative_cases() -> None:
    results = run_correlation_scenarios()

    assert all(result.passed for result in results)
    assert any("correlate" in result.scenario for result in results)
    assert any("separate" in result.scenario for result in results)
    assert any("PID reuse" in result.scenario for result in results)
