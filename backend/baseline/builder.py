from dataclasses import dataclass

from backend.database.repository import SQLiteRepository
from backend.features.extractor import FeatureExtractor, normalize_executable_path
from backend.features.models import ApplicationFeatureSet, SignalTraceProfile


@dataclass(frozen=True)
class BaselineSettings:
    minimum_observations: int = 5
    profile_version: int | None = None


class BaselineBuilder:
    def __init__(
        self,
        repository: SQLiteRepository,
        settings: BaselineSettings | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings or BaselineSettings()

        if self.settings.minimum_observations < 1:
            raise ValueError("minimum_observations must be positive")

    def build(self, application_identity: str) -> SignalTraceProfile | None:
        feature_bundle = FeatureExtractor(self.repository).extract()
        canonical_identity = normalize_executable_path(application_identity)

        feature_set = next(
            (
                item
                for item in feature_bundle.profiles
                if item.application_identity == canonical_identity
            ),
            None,
        )

        if feature_set is None:
            return None

        version = (
            self.settings.profile_version
            or self.repository.next_profile_version(canonical_identity)
        )

        profile = _profile_from_features(
            feature_set,
            version,
            self.settings.minimum_observations,
        )

        self.repository.save_profile(profile)
        return profile

    def rebuild(self, application_identity: str) -> SignalTraceProfile | None:
        return self.build(application_identity)

    def load(
        self,
        application_identity: str,
        version: int | None = None,
    ) -> SignalTraceProfile | None:
        canonical_identity = normalize_executable_path(application_identity)
        return self.repository.load_profile(canonical_identity, version)


def _profile_from_features(
    features: ApplicationFeatureSet,
    version: int,
    minimum_observations: int,
) -> SignalTraceProfile:
    status = (
        "ready"
        if features.observation_count >= minimum_observations
        else "insufficient_data"
    )

    return SignalTraceProfile(
        application_identity=features.application_identity,
        profile_version=version,
        observation_start=features.first_seen,
        observation_end=features.last_seen,
        observation_count=features.observation_count,
        process_dna={
            "launch_frequency": features.process_launch_frequency,
            "child_process_frequency": features.child_process_frequency,
            "parent_process_patterns": features.parent_process_patterns,
            "process_tree_depth": features.process_tree_depth,
            "executable_frequency": features.executable_frequency,
            "hash_frequency": features.hash_frequency,
        },
        network_dna={
            "destination_frequency": features.network_destination_frequency,
            "destination_ports": features.network_destination_ports,
            "protocol_frequency": features.network_protocol_frequency,
            "scope_frequency": features.network_scope_frequency,
            "first_seen": features.network_first_seen,
            "last_seen": features.network_last_seen,
        },
        file_dna={
            "directory_frequency": features.file_directory_frequency,
            "path_frequency": features.file_path_frequency,
            "extension_frequency": features.file_extension_frequency,
        },
        execution_dna={
            "command_pattern_frequency": features.command_pattern_frequency,
            "command_category_frequency": features.command_category_frequency,
            "executable_locations": features.executable_frequency,
        },
        temporal_dna={
            "activity_by_hour": features.activity_by_hour,
            "activity_by_weekday": features.activity_by_weekday,
            "first_seen": features.first_seen,
            "last_seen": features.last_seen,
        },
        privilege_dna={
            "frequency": features.privilege_frequency,
            "available": features.privilege_data_available,
        },
        quality=features.quality,
        profile_status=status,
    )