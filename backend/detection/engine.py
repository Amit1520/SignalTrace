import hashlib
from datetime import datetime

from backend.features.models import SignalTraceProfile

from .detector import FeatureSchemaMismatchError, InsufficientBaselineError, StatisticalDetector
from .deterministic import compare_observation
from .models import (
    BaselineComparison,
    BehaviorObservation,
    DetectionOutcome,
    DetectionResult,
    FEATURE_SCHEMA_VERSION,
    Severity,
)
from .vector import validate_vector_schema


class DetectionConfig:
    def __init__(
        self,
        minimum_profile_observations: int = 5,
        low_threshold: float = 0.25,
        medium_threshold: float = 0.55,
        high_threshold: float = 0.80,
    ) -> None:
        self.minimum_profile_observations = minimum_profile_observations
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold


class BehavioralDetector:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def detect(
        self,
        observation: BehaviorObservation,
        profile: SignalTraceProfile,
        statistical_detector: StatisticalDetector | None = None,
    ) -> DetectionOutcome:
        if observation.feature_schema_version != FEATURE_SCHEMA_VERSION:
            return DetectionOutcome(reason="incompatible feature schema", incompatible_schema=True)
        if profile.profile_schema_version != "1.0":
            return DetectionOutcome(reason="incompatible profile schema", incompatible_schema=True)
        if profile.observation_count < self.config.minimum_profile_observations or profile.profile_status == "insufficient_data":
            return DetectionOutcome(reason="insufficient baseline", insufficient_baseline=True)
        if not validate_vector_schema(observation):
            return DetectionOutcome(reason="incompatible feature vector", incompatible_schema=True)
        signals = compare_observation(observation, profile)
        deterministic = min(1.0, sum(signal.contribution for signal in signals) / 2.0)
        statistical = 0.0
        model_version = None
        if statistical_detector is not None:
            try:
                statistical = statistical_detector.score(observation)
                model_version = statistical_detector.config.model_version
            except (InsufficientBaselineError, FeatureSchemaMismatchError) as error:
                return DetectionOutcome(reason=str(error), insufficient_baseline=isinstance(error, InsufficientBaselineError), incompatible_schema=isinstance(error, FeatureSchemaMismatchError))
        score = min(1.0, deterministic * 0.65 + statistical * 0.35)
        if len({signal.category for signal in signals}) >= 3:
            score = min(1.0, score + 0.1)
        severity = _severity(score, len(signals), self.config)
        confidence = min(1.0, 0.5 + min(0.5, profile.observation_count / 100.0))
        detection_id = _detection_id(observation, profile, score)
        result = DetectionResult(
            detection_id=detection_id,
            application_identity=observation.application_identity,
            timestamp=observation.timestamp,
            anomaly_score=score,
            severity=severity,
            confidence=confidence,
            statistical_contribution=statistical * 0.35,
            deterministic_contribution=deterministic * 0.65,
            contributing_signals=signals,
            baseline_comparison=BaselineComparison(
                profile_version=profile.profile_version,
                profile_status=profile.profile_status,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                observation_count=profile.observation_count,
                compatible=True,
            ),
            provenance_references=observation.provenance_references,
            model_version=model_version,
            reason="behavioral deviation evidence" if score >= self.config.low_threshold else "no significant behavioral deviation",
            host=observation.observed_features.get("host"),
            process_guid=observation.observed_features.get("process_guid"),
            parent_process_guid=observation.observed_features.get("parent_process_guid"),
            process_id=observation.observed_features.get("process_id"),
            image_path=observation.observed_features.get("image_path"),
        )
        return DetectionOutcome(result=result)


def _severity(score: float, signal_count: int, config: DetectionConfig) -> Severity:
    if score >= config.high_threshold and signal_count >= 2:
        return Severity.HIGH
    if score >= config.medium_threshold and signal_count >= 1:
        return Severity.MEDIUM
    if score >= config.low_threshold and signal_count >= 1:
        return Severity.LOW
    return Severity.NORMAL


def _detection_id(observation: BehaviorObservation, profile: SignalTraceProfile, score: float) -> str:
    value = "|".join((observation.application_identity, str(observation.timestamp), str(profile.profile_version), f"{score:.8f}", *observation.provenance_references))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
