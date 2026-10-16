from enum import Enum


class IngestionErrorCode(str, Enum):
    SYSMON_UNAVAILABLE = "sysmon_unavailable"
    ACCESS_FAILURE = "permission_access_failure"
    MALFORMED_EVENT = "malformed_event"
    UNSUPPORTED_EVENT_ID = "unsupported_event_id"
    DUPLICATE_EVENT = "duplicate_event"
    CHECKPOINT_CORRUPTION = "checkpoint_corruption"
    EVENT_SOURCE_GAP = "event_source_gap_or_reset"


class IngestionError(Exception):
    def __init__(self, code: IngestionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SysmonUnavailableError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.SYSMON_UNAVAILABLE, message)


class AccessFailureError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.ACCESS_FAILURE, message)


class MalformedEventError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.MALFORMED_EVENT, message)


class UnsupportedEventError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.UNSUPPORTED_EVENT_ID, message)


class DuplicateEventError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.DUPLICATE_EVENT, message)


class CheckpointCorruptError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.CHECKPOINT_CORRUPTION, message)


class EventSourceGapError(IngestionError):
    def __init__(self, message: str) -> None:
        super().__init__(IngestionErrorCode.EVENT_SOURCE_GAP, message)
