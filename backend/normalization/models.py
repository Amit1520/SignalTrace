from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class EventKind(str, Enum):
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACTIVITY = "file_activity"


class EventProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = "sysmon"
    channel: str
    provider: str | None = None
    source_record_id: str | None = None
    raw_event_hash: str


class NormalizedEventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EventKind
    timestamp: datetime | None = None
    host: str | None = None
    event_id: int
    record_id: str | None = None
    process_guid: str | None = None
    process_id: int | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    parent_image: str | None = None
    image: str | None = None
    command_line: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    provenance: EventProvenance


class ProcessCreationEvent(NormalizedEventBase):
    kind: Literal[EventKind.PROCESS_CREATION] = EventKind.PROCESS_CREATION
    current_directory: str | None = None
    user: str | None = None
    integrity_level: str | None = None


class NetworkConnectionEvent(NormalizedEventBase):
    kind: Literal[EventKind.NETWORK_CONNECTION] = EventKind.NETWORK_CONNECTION
    protocol: str | None = None
    initiated: bool | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_hostname: str | None = None
    destination_port: int | None = None


class FileActivityEvent(NormalizedEventBase):
    kind: Literal[EventKind.FILE_ACTIVITY] = EventKind.FILE_ACTIVITY
    target_filename: str | None = None
    creation_utc: datetime | None = None


NormalizedEvent = Annotated[
    ProcessCreationEvent | NetworkConnectionEvent | FileActivityEvent,
    Field(discriminator="kind"),
]
