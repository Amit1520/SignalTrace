from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.detection.models import Severity


class IncidentStatus(str, Enum):
    OPEN = "open"
    UPDATED = "updated"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ProcessNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    process_guid: str | None = None
    process_id: int | None = None
    image_path: str | None = None
    parent_guid: str | None = None
    parent_pid: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    hash: str | None = None


class IncidentEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_reference: str
    timestamp: datetime | None = None
    event_category: str
    process_guid: str | None = None
    parent_process_guid: str | None = None
    description: str
    severity: Severity
    contribution: float = Field(ge=0)
    provenance: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    application_identity: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    duration: timedelta | None = None
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    status: IncidentStatus
    anomaly_count: int = Field(ge=0)
    signal_count: int = Field(ge=0)
    affected_processes: list[str] = Field(default_factory=list)
    process_chain: list[ProcessNode] = Field(default_factory=list)
    timeline: list[IncidentEvent] = Field(default_factory=list)
    contributing_evidence: list[str] = Field(default_factory=list)
    correlation_version: str = "1.0"
