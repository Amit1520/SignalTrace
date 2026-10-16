import math
import pickle
import io
from dataclasses import dataclass

from sklearn.ensemble import IsolationForest

from .models import BehaviorObservation, FEATURE_SCHEMA_VERSION
from .vector import VECTOR_FEATURE_NAMES, validate_vector_schema


@dataclass(frozen=True)
class StatisticalConfig:
    minimum_observations: int = 10
    contamination: str | float = "auto"
    random_state: int = 42
    model_version: str = "isolation-forest-1"


class InsufficientBaselineError(ValueError):
    pass


class FeatureSchemaMismatchError(ValueError):
    pass


class StatisticalDetector:
    def __init__(self, config: StatisticalConfig | None = None) -> None:
        self.config = config or StatisticalConfig()
        self.model: IsolationForest | None = None
        self.feature_schema_version = FEATURE_SCHEMA_VERSION

    @property
    def is_trained(self) -> bool:
        return self.model is not None

    def train(self, observations: list[BehaviorObservation]) -> None:
        if len(observations) < self.config.minimum_observations:
            raise InsufficientBaselineError("insufficient baseline")
        if any(not validate_vector_schema(item) for item in observations):
            raise FeatureSchemaMismatchError("feature schema is incompatible with detector")
        matrix = [[item.feature_vector[name] for name in VECTOR_FEATURE_NAMES] for item in observations]
        self.model = IsolationForest(
            contamination=self.config.contamination,
            random_state=self.config.random_state,
            n_estimators=100,
        )
        self.model.fit(matrix)

    def score(self, observation: BehaviorObservation) -> float:
        if self.model is None:
            raise InsufficientBaselineError("detector has not been trained")
        if not validate_vector_schema(observation):
            raise FeatureSchemaMismatchError("feature schema is incompatible with detector")
        vector = [[observation.feature_vector[name] for name in VECTOR_FEATURE_NAMES]]
        decision = float(self.model.decision_function(vector)[0])
        return _bounded_sigmoid(-decision * 5.0)

    def save(self, repository, application_identity: str, profile_version: int) -> None:
        if self.model is None:
            raise InsufficientBaselineError("cannot save an untrained detector")
        repository.save_detector_model(
            application_identity=application_identity,
            profile_version=profile_version,
            model_version=self.config.model_version,
            feature_schema_version=self.feature_schema_version,
            metadata={
                "contamination": self.config.contamination,
                "random_state": self.config.random_state,
                "minimum_observations": self.config.minimum_observations,
                "feature_names": list(VECTOR_FEATURE_NAMES),
            },
            model_blob=pickle.dumps(self.model),
        )

    @classmethod
    def load(cls, repository, application_identity: str, profile_version: int) -> "StatisticalDetector | None":
        record = repository.load_detector_model(application_identity, profile_version)
        if record is None:
            return None
        if record["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise FeatureSchemaMismatchError("stored model feature schema is incompatible")
        metadata = record["metadata"]
        config = StatisticalConfig(
            minimum_observations=metadata["minimum_observations"],
            contamination=metadata["contamination"],
            random_state=metadata["random_state"],
            model_version=record["model_version"],
        )
        detector = cls(config)
        detector.model = _safe_model_loads(record["model_blob"])
        return detector


def _bounded_sigmoid(value: float) -> float:
    value = max(-20.0, min(20.0, value))
    return max(0.0, min(1.0, 1.0 / (1.0 + math.exp(-value))))


class _RestrictedUnpickler(pickle.Unpickler):
    _allowed_prefixes = ("builtins", "collections", "copyreg", "numpy", "scipy", "sklearn")

    def find_class(self, module: str, name: str):
        if module == "builtins" or module.startswith(self._allowed_prefixes[1:]):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"model class is not allowed: {module}.{name}")


def _safe_model_loads(blob: bytes) -> IsolationForest:
    return _RestrictedUnpickler(io.BytesIO(blob)).load()
