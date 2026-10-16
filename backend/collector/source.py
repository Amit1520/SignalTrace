from dataclasses import dataclass
from typing import Iterator, Protocol
import sys
import xml.etree.ElementTree as ET

from .errors import AccessFailureError, SysmonUnavailableError


@dataclass(frozen=True)
class RawSysmonEvent:
    xml: str
    source: str = "sysmon"
    channel: str = "Microsoft-Windows-Sysmon/Operational"


class SysmonEventSource(Protocol):
    def read_events(
        self,
        after_record_id: str | None,
        limit: int,
    ) -> Iterator[RawSysmonEvent]:
        """Read events without changing the Windows event source."""

    def get_latest_record_id(self) -> str | None:
        """Return the newest currently available Sysmon EventRecordID."""


class WindowsSysmonEventSource:
    """Read Sysmon Operational events through the read-only Windows Event Log API."""

    def __init__(
        self,
        channel: str = "Microsoft-Windows-Sysmon/Operational",
    ) -> None:
        self.channel = channel

    def check_availability(self):
        from backend.api.status import ComponentStatus

        if sys.platform != "win32":
            return ComponentStatus(
                status="unavailable",
                detail="Windows Sysmon source requires Windows",
            )

        try:
            import win32evtlog  # type: ignore[import-not-found]
        except ImportError:
            return ComponentStatus(
                status="unavailable",
                detail="pywin32 is not installed",
            )

        handle = None
        try:
            handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryForwardDirection,
                "*",
            )
            return ComponentStatus(
                status="available",
                detail=f"read-only channel available: {self.channel}",
            )
        except PermissionError:
            return ComponentStatus(
                status="unavailable",
                detail="access to the Sysmon channel was denied",
            )
        except OSError:
            return ComponentStatus(
                status="unavailable",
                detail="Sysmon channel is unavailable",
            )
        finally:
            if handle is not None:
                handle.Close()

    def get_latest_record_id(self) -> str | None:
        """Return the newest currently available Sysmon EventRecordID."""

        if sys.platform != "win32":
            raise SysmonUnavailableError(
                "Windows Sysmon collection requires Windows"
            )

        try:
            import win32evtlog  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SysmonUnavailableError(
                "pywin32 is required for Windows Sysmon collection"
            ) from exc

        handle = None

        try:
            handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryReverseDirection,
                "*",
            )

            events = win32evtlog.EvtNext(handle, 1)

            if not events:
                return None

            xml = win32evtlog.EvtRender(
                events[0],
                win32evtlog.EvtRenderEventXml,
            )

            root = ET.fromstring(xml)

            for element in root.iter():
                if element.tag.endswith("EventRecordID"):
                    return element.text

            return None

        except PermissionError as exc:
            raise AccessFailureError(
                "access to the Sysmon event channel was denied"
            ) from exc
        except OSError as exc:
            raise SysmonUnavailableError(
                f"Sysmon event source could not be read: {exc}"
            ) from exc
        except ET.ParseError as exc:
            raise SysmonUnavailableError(
                "Sysmon event XML could not be parsed"
            ) from exc
        finally:
            if handle is not None:
                handle.Close()

    def read_events(
        self,
        after_record_id: str | None,
        limit: int,
    ) -> Iterator[RawSysmonEvent]:
        if sys.platform != "win32":
            raise SysmonUnavailableError(
                "Windows Sysmon collection requires Windows"
            )

        try:
            import win32evtlog  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SysmonUnavailableError(
                "pywin32 is required for Windows Sysmon collection"
            ) from exc

        query = "*"

        if after_record_id is not None:
            try:
                record_id = int(after_record_id)
            except ValueError as exc:
                raise SysmonUnavailableError(
                    "checkpoint record ID is not numeric"
                ) from exc

            if record_id < 0:
                raise SysmonUnavailableError(
                    "checkpoint record ID cannot be negative"
                )

            query = f"*[System[(EventRecordID > {record_id})]]"

        handle = None

        try:
            handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryForwardDirection,
                query,
            )

            for event in win32evtlog.EvtNext(handle, limit):
                yield RawSysmonEvent(
                    xml=win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml,
                    ),
                    channel=self.channel,
                )

        except PermissionError as exc:
            raise AccessFailureError(
                "access to the Sysmon event channel was denied"
            ) from exc
        except OSError as exc:
            raise SysmonUnavailableError(
                f"Sysmon event source could not be read: {exc}"
            ) from exc
        finally:
            if handle is not None:
                handle.Close()