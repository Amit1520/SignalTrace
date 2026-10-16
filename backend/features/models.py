from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FeatureQuality(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: int = Field(ge=0)
    complete_timestamps: int = Field(ge=0)
    missing_timestamp_count: int = Field(ge=0)
    missing_application_identity_count: int = Field(ge=0)


class ApplicationFeatureSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_identity: str
    observation_count: int = Field(ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    process_launch_frequency: dict[str, int] = Field(default_factory=dict)
    child_process_frequency: dict[str, int] = Field(default_factory=dict)
    parent_process_patterns: dict[str, int] = Field(default_factory=dict)
    process_tree_depth: dict[str, int] = Field(default_factory=dict)
    executable_frequency: dict[str, int] = Field(default_factory=dict)
    hash_frequency: dict[str, int] = Field(default_factory=dict)
    network_destination_frequency: dict[str, int] = Field(default_factory=dict)
    network_destination_ports: dict[str, int] = Field(default_factory=dict)
    network_protocol_frequency: dict[str, int] = Field(default_factory=dict)
    network_scope_frequency: dict[str, int] = Field(default_factory=dict)
    network_first_seen: dict[str, datetime] = Field(default_factory=dict)
    network_last_seen: dict[str, datetime] = Field(default_factory=dict)
    file_directory_frequency: dict[str, int] = Field(default_factory=dict)
    file_path_frequency: dict[str, int] = Field(default_factory=dict)
    file_extension_frequency: dict[str, int] = Field(default_factory=dict)
    command_pattern_frequency: dict[str, int] = Field(default_factory=dict)
    command_category_frequency: dict[str, int] = Field(default_factory=dict)
    activity_by_hour: dict[str, int] = Field(default_factory=dict)
    activity_by_weekday: dict[str, int] = Field(default_factory=dict)
    privilege_frequency: dict[str, int] = Field(default_factory=dict)
    privilege_data_available: bool = False
    quality: FeatureQuality


class FeatureBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: list[ApplicationFeatureSet]
    unassigned_observations: int = Field(default=0, ge=0)


class SignalTraceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_identity: str
    profile_version: int = Field(ge=1)
    observation_start: datetime | None = None
    observation_end: datetime | None = None
    observation_count: int = Field(ge=0)
    process_dna: dict[str, Any] = Field(default_factory=dict)
    network_dna: dict[str, Any] = Field(default_factory=dict)
    file_dna: dict[str, Any] = Field(default_factory=dict)
    execution_dna: dict[str, Any] = Field(default_factory=dict)
    temporal_dna: dict[str, Any] = Field(default_factory=dict)
    privilege_dna: dict[str, Any] = Field(default_factory=dict)
    quality: FeatureQuality
    profile_status: str
    profile_schema_version: str = "1.0"
