from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


FEATURE_SCHEMA_VERSION = "1.0"
DETECTOR_VERSION = "1.0"


class SignalCategory(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    EXECUTION = "execution"
    TEMPORAL = "temporal"
    PRIVILEGE = "privilege"


class Severity(str, Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class BehaviorObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_identity: str
    timestamp: datetime | None = None
    feature_vector: dict[str, float]
    observed_features: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    provenance_references: list[str] = Field(default_factory=list)
    feature_schema_version: str = FEATURE_SCHEMA_VERSION


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: SignalCategory
    signal_type: str
    observed_value: Any = None
    baseline_value: Any = None
    deviation: str
    weight: float = Field(ge=0)
    contribution: float = Field(ge=0)
    evidence_reference: str | None = None


class BaselineComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_version: int
    profile_status: str
    feature_schema_version: str
    observation_count: int
    compatible: bool


class DetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_id: str
    application_identity: str
    timestamp: datetime | None = None
    anomaly_score: float = Field(ge=0, le=1)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    statistical_contribution: float = Field(ge=0, le=1)
    deterministic_contribution: float = Field(ge=0, le=1)
    contributing_signals: list[Signal] = Field(default_factory=list)
    baseline_comparison: BaselineComparison
    provenance_references: list[str] = Field(default_factory=list)
    detector_version: str = DETECTOR_VERSION
    model_version: str | None = None
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    reason: str | None = None
    host: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    process_id: int | None = None
    image_path: str | None = None


class DetectionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: DetectionResult | None = None
    reason: str | None = None
    insufficient_baseline: bool = False
    incompatible_schema: bool = False
