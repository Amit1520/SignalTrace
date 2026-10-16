from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


AI_SCHEMA_VERSION = "1.0"
PROMPT_VERSION = "1.0"
MAX_EXPLANATION_CHARS = 8_000


class GenerationStatus(str, Enum):
    GENERATED = "generated"
    FALLBACK = "fallback"
    FAILED = "failed"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference: str
    category: str
    observation: str
    baseline: str | None = None
    deviation: str


class ExplanationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    application_identity: str
    severity: str
    deviation_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    signals: list[EvidenceItem] = Field(default_factory=list)
    process_chain: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    provenance_references: list[str] = Field(default_factory=list)
    profile_version: int | None = None
    detector_version: str | None = None
    feature_schema_version: str | None = None
    known_limitations: list[str] = Field(default_factory=list)


class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    summary: str
    what_changed: list[str] = Field(default_factory=list)
    why_unusual: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    recommended_investigation: list[str] = Field(default_factory=list)
    generated_at: datetime
    provider: str
    model_identifier: str
    prompt_version: str = PROMPT_VERSION
    schema_version: str = AI_SCHEMA_VERSION
    generation_status: GenerationStatus


class ExplanationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation: Explanation | None = None
    error: str | None = None
    generation_status: GenerationStatus
