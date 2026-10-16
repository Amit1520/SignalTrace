from pathlib import Path

import pytest

from backend.collector.checkpoint import Checkpoint, JsonCheckpointStore
from backend.collector.collector import ReadOnlySysmonCollector
from backend.collector.errors import (
    CheckpointCorruptError,
    EventSourceGapError,
    IngestionErrorCode,
    MalformedEventError,
    SysmonUnavailableError,
    UnsupportedEventError,
)
from backend.collector.source import RawSysmonEvent, WindowsSysmonEventSource
from backend.normalization.models import (
    EventKind,
    FileActivityEvent,
    NetworkConnectionEvent,
    ProcessCreationEvent,
)
from backend.parser.sysmon import parse_sysmon_event


PROCESS_XML = r"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-14T10:11:12.000Z" />
    <EventRecordID>42</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>test-host</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{abc}</Data>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
    <Data Name="CommandLine">notepad.exe sample.txt</Data>
    <Data Name="ParentProcessGuid">{parent}</Data>
    <Data Name="ParentProcessId">100</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="Hashes">SHA256=ABC123;MD5=DEF456</Data>
    <Data Name="User">TEST\user</Data>
  </EventData>
</Event>
"""

NETWORK_XML = PROCESS_XML.replace(
    "<EventID>1</EventID>",
    "<EventID>3</EventID>",
).replace(
    '<Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>',
    '<Data Name="Protocol">tcp</Data>\n'
    '    <Data Name="DestinationIp">203.0.113.10</Data>\n'
    '    <Data Name="DestinationPort">443</Data>',
)

FILE_XML = PROCESS_XML.replace(
    "<EventID>1</EventID>",
    "<EventID>11</EventID>",
).replace(
    '<Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>',
    '<Data Name="TargetFilename">C:\\Temp\\sample.txt</Data>',
)


def raw(xml: str) -> RawSysmonEvent:
    return RawSysmonEvent(xml=xml)


def test_valid_process_xml_preserves_normalized_fields_and_provenance() -> None:
    event = parse_sysmon_event(raw(PROCESS_XML))

    assert isinstance(event, ProcessCreationEvent)
    assert event.kind is EventKind.PROCESS_CREATION
    assert event.record_id == "42"
    assert event.process_id == 1234
    assert event.parent_process_id == 100
    assert event.hashes == {"SHA256": "ABC123", "MD5": "DEF456"}
    assert event.provenance.source == "sysmon"
    assert event.provenance.source_record_id == "42"
    assert len(event.provenance.raw_event_hash) == 64


def test_network_and_file_events_are_supported() -> None:
    network = parse_sysmon_event(raw(NETWORK_XML))
    file_event = parse_sysmon_event(raw(FILE_XML))

    assert isinstance(network, NetworkConnectionEvent)
    assert network.destination_ip == "203.0.113.10"
    assert network.destination_port == 443

    assert isinstance(file_event, FileActivityEvent)
    assert file_event.target_filename == r"C:\Temp\sample.txt"


def test_missing_fields_are_normalized_without_crashing() -> None:
    minimal = PROCESS_XML.replace(
        '<Data Name="ProcessId">1234</Data>',
        "",
    )

    event = parse_sysmon_event(raw(minimal))

    assert isinstance(event, ProcessCreationEvent)
    assert event.process_id is None
    assert event.command_line == "notepad.exe sample.txt"


def test_malformed_xml_is_classified() -> None:
    with pytest.raises(MalformedEventError) as error:
        parse_sysmon_event(raw("<Event>"))

    assert error.value.code is IngestionErrorCode.MALFORMED_EVENT


def test_unsupported_event_id_is_classified() -> None:
    with pytest.raises(UnsupportedEventError) as error:
        parse_sysmon_event(
            raw(
                PROCESS_XML.replace(
                    "<EventID>1</EventID>",
                    "<EventID>22</EventID>",
                )
            )
        )

    assert error.value.code is IngestionErrorCode.UNSUPPORTED_EVENT_ID


def test_checkpoint_save_load_and_corruption_reset(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    store = JsonCheckpointStore(path)

    store.save(Checkpoint("42"))

    assert store.load_or_reset() == Checkpoint("42")

    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(CheckpointCorruptError):
        store.load_or_reset()

    assert path.with_suffix(".json.invalid").exists()


def test_collector_returns_checkpoint_and_prevents_duplicates(
    tmp_path: Path,
) -> None:
    class FixtureSource:
        def __init__(self) -> None:
            self.calls = 0

        def read_events(
            self,
            after_record_id: str | None,
            limit: int,
        ):
            self.calls += 1

            if self.calls == 1:
                return iter([raw(PROCESS_XML)])

            return iter([raw(PROCESS_XML)])

    source = FixtureSource()

    checkpoint_store = JsonCheckpointStore(
        tmp_path / "checkpoint.json",
    )

    collector = ReadOnlySysmonCollector(
        source,
        checkpoint_store,
    )

    first = collector.collect_once()

    # collect_once() intentionally returns a candidate checkpoint.
    # The caller commits it only after successful persistence.
    checkpoint_store.save(first.checkpoint)

    second = collector.collect_once()

    assert len(first.events) == 1
    assert first.checkpoint == Checkpoint("42")

    assert not second.events
    assert [error.code for error in second.errors] == [
        IngestionErrorCode.DUPLICATE_EVENT
    ]


def test_collector_reports_a_lower_record_id_as_a_source_gap(
    tmp_path: Path,
) -> None:
    class ResettingSource:
        def read_events(
            self,
            after_record_id: str | None,
            limit: int,
        ):
            if after_record_id is None:
                return iter([raw(PROCESS_XML)])

            return iter(
                [
                    raw(
                        PROCESS_XML.replace(
                            "<EventRecordID>42</EventRecordID>",
                            "<EventRecordID>41</EventRecordID>",
                        )
                    )
                ]
            )

    checkpoint_store = JsonCheckpointStore(
        tmp_path / "checkpoint.json",
    )

    collector = ReadOnlySysmonCollector(
        ResettingSource(),
        checkpoint_store,
    )

    first = collector.collect_once()

    # Commit the candidate checkpoint before the next collection cycle.
    checkpoint_store.save(first.checkpoint)

    result = collector.collect_once()

    assert not result.events
    assert [error.code for error in result.errors] == [
        IngestionErrorCode.EVENT_SOURCE_GAP
    ]
    assert isinstance(result.errors[0], EventSourceGapError)


def test_sysmon_is_unavailable_off_windows() -> None:
    if __import__("sys").platform == "win32":
        pytest.skip("non-Windows behavior only")

    with pytest.raises(SysmonUnavailableError) as error:
        list(WindowsSysmonEventSource().read_events(None, 1))

    assert error.value.code is IngestionErrorCode.SYSMON_UNAVAILABLE


@pytest.mark.skipif(
    __import__("sys").platform != "win32",
    reason="requires Windows Sysmon",
)
def test_windows_sysmon_integration_requires_real_setup() -> None:
    source = WindowsSysmonEventSource()
    availability = source.check_availability()

    if availability.status != "available":
        pytest.skip(availability.detail)

    events = list(source.read_events(None, 3))

    assert source.channel == "Microsoft-Windows-Sysmon/Operational"
    assert len(events) <= 3
    assert all(event.channel == source.channel for event in events)
    assert all(event.xml.startswith("<") for event in events)


def test_collector_advances_checkpoint_past_unsupported_event(
    tmp_path: Path,
) -> None:
    unsupported_xml = (
        PROCESS_XML.replace(
            "<EventID>1</EventID>",
            "<EventID>5</EventID>",
        )
        .replace(
            "<EventRecordID>42</EventRecordID>",
            "<EventRecordID>43</EventRecordID>",
        )
    )

    class FixtureSource:
        def read_events(
            self,
            after_record_id: str | None,
            limit: int,
        ):
            if after_record_id is None:
                return iter([raw(unsupported_xml)])

            return iter([])

    checkpoint_store = JsonCheckpointStore(
        tmp_path / "checkpoint.json",
    )

    collector = ReadOnlySysmonCollector(
        FixtureSource(),
        checkpoint_store,
    )

    first = collector.collect_once()

    # Unsupported events are safely examined and therefore produce
    # a candidate checkpoint. Commit it before the next cycle.
    checkpoint_store.save(first.checkpoint)

    second = collector.collect_once()

    assert not first.events
    assert first.unsupported_events_skipped == 1
    assert not first.errors
    assert first.checkpoint == Checkpoint("43")

    assert not second.events
    assert second.unsupported_events_skipped == 0
    assert not second.errors
    assert second.checkpoint == Checkpoint("43")
