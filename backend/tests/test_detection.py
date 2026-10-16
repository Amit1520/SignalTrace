from datetime import timedelta

import pytest

from backend.baseline.builder import BaselineBuilder, BaselineSettings
from backend.database.repository import SQLiteRepository
from backend.detection.detector import (
    FeatureSchemaMismatchError,
    InsufficientBaselineError,
    StatisticalConfig,
    StatisticalDetector,
)
from backend.detection.engine import BehavioralDetector, DetectionConfig
from backend.detection.models import BehaviorObservation, FEATURE_SCHEMA_VERSION, Severity
from backend.detection.vector import VECTOR_FEATURE_NAMES, observation_from_row
from backend.tests.test_database import file_event, network_event, process_event


def profile_for(repository):
    repository.insert_events([process_event(), network_event(), file_event()])
    return BaselineBuilder(repository, BaselineSettings(minimum_observations=1)).build(
        "c:/windows/system32/cmd.exe"
    )


def test_normal_observation_has_no_deterministic_signals(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        profile = profile_for(repository)
        row = repository.list_events("network_connection")[0]
        observation = observation_from_row("network_connection", row, profile)
        outcome = BehavioralDetector(DetectionConfig(minimum_profile_observations=1)).detect(observation, profile)

    assert outcome.result is not None
    assert outcome.result.contributing_signals == []
    assert outcome.result.severity is Severity.NORMAL


def test_new_destination_creates_explainable_signal(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        profile = profile_for(repository)
        changed = network_event("new-destination")
        changed.destination_ip = "8.8.8.8"
        repository.insert_events([changed])
        row = repository.list_events("network_connection")[-1]
        observation = observation_from_row("network_connection", row, profile)
        outcome = BehavioralDetector(DetectionConfig(minimum_profile_observations=1)).detect(observation, profile)

    assert outcome.result is not None
    assert any(signal.signal_type == "new_destination" for signal in outcome.result.contributing_signals)
    assert outcome.result.reason == "behavioral deviation evidence"


def test_insufficient_profile_is_not_forced_into_anomaly(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        repository.insert_events([process_event()])
        profile = BaselineBuilder(repository, BaselineSettings(minimum_observations=5)).build(
            "c:/windows/system32/cmd.exe"
        )
        row = repository.list_events("process_creation")[0]
        observation = observation_from_row("process_creation", row, profile)
        outcome = BehavioralDetector().detect(observation, profile)

    assert outcome.result is None
    assert outcome.insufficient_baseline is True
    assert outcome.reason == "insufficient baseline"


def test_statistical_training_is_deterministic_and_persistable(tmp_path) -> None:
    observations = [
        BehaviorObservation(
            application_identity="app",
            feature_vector={name: float(index % 2) for index, name in enumerate(VECTOR_FEATURE_NAMES)},
            provenance_references=[str(index)],
        )
        for index in range(10)
    ]
    config = StatisticalConfig(minimum_observations=5, random_state=7)
    first = StatisticalDetector(config)
    second = StatisticalDetector(config)
    first.train(observations)
    second.train(observations)
    target = observations[0].model_copy(deep=True)

    assert first.score(target) == second.score(target)
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        first.save(repository, "app", 1)
        loaded = StatisticalDetector.load(repository, "app", 1)
        assert loaded is not None
        assert loaded.score(target) == first.score(target)


def test_statistical_detector_rejects_sparse_and_incompatible_data() -> None:
    observation = BehaviorObservation(
        application_identity="app",
        feature_vector={name: 0.0 for name in VECTOR_FEATURE_NAMES},
    )
    detector = StatisticalDetector(StatisticalConfig(minimum_observations=2))
    with pytest.raises(InsufficientBaselineError):
        detector.train([observation])
    incompatible = observation.model_copy(update={"feature_schema_version": "0.0"})
    with pytest.raises(FeatureSchemaMismatchError):
        detector.train([incompatible, incompatible])


def test_detection_evidence_persists(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        profile = profile_for(repository)
        row = repository.list_events("network_connection")[0]
        observation = observation_from_row("network_connection", row, profile)
        result = BehavioralDetector(DetectionConfig(minimum_profile_observations=1)).detect(observation, profile).result
        repository.save_detection(result, result.contributing_signals)
        stored = repository.connection.execute("SELECT detection_id, profile_version FROM anomalies").fetchone()

    assert stored["detection_id"] == result.detection_id
    assert stored["profile_version"] == profile.profile_version
