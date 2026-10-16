from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from backend.database.config import DatabaseSettings
from backend.database.errors import DatabaseValidationError
from backend.database.repository import SQLiteRepository
from backend.normalization.models import (
    EventProvenance,
    FileActivityEvent,
    NetworkConnectionEvent,
    ProcessCreationEvent,
)


TIMESTAMP = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)


def provenance(record_id: str, digest: str | None = None) -> EventProvenance:
    return EventProvenance(
        channel="Microsoft-Windows-Sysmon/Operational",
        source_record_id=record_id,
        raw_event_hash=digest or f"hash-{record_id}",
    )


def process_event(record_id: str = "1") -> ProcessCreationEvent:
    return ProcessCreationEvent(
        timestamp=TIMESTAMP,
        host="host-1",
        event_id=1,
        record_id=record_id,
        process_guid="{process-1}",
        process_id=100,
        parent_process_guid="{parent-1}",
        parent_process_id=50,
        parent_image=r"C:\Windows\explorer.exe",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        hashes={"SHA256": "abc"},
        provenance=provenance(record_id),
        current_directory=r"C:\Windows",
        user="HOST\\user",
        integrity_level="Medium",
    )


def network_event(record_id: str = "2") -> NetworkConnectionEvent:
    return NetworkConnectionEvent(
        timestamp=TIMESTAMP + timedelta(seconds=1),
        host="host-1",
        event_id=3,
        record_id=record_id,
        process_guid="{process-1}",
        process_id=100,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        hashes={"SHA256": "abc"},
        provenance=provenance(record_id),
        protocol="tcp",
        initiated=True,
        source_ip="192.0.2.10",
        source_port=50000,
        destination_ip="203.0.113.10",
        destination_hostname="example.invalid",
        destination_port=443,
    )


def file_event(record_id: str = "3") -> FileActivityEvent:
    return FileActivityEvent(
        timestamp=TIMESTAMP + timedelta(seconds=2),
        host="host-1",
        event_id=11,
        record_id=record_id,
        process_guid="{process-1}",
        process_id=100,
        image=r"C:\Windows\System32\cmd.exe",
        provenance=provenance(record_id),
        target_filename=r"C:\Temp\output.txt",
        creation_utc=TIMESTAMP + timedelta(seconds=2),
    )


def test_database_initializes_expected_schema_and_indexes(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        tables = {
            row["name"]
            for row in repository.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row["name"]
            for row in repository.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }

    assert {"applications", "process_events", "network_events", "file_events", "ingestion_events"} <= tables
    assert "idx_process_guid" in indexes
    assert "idx_network_destination" in indexes


def test_insert_retrieve_relationships_and_provenance(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        result = repository.insert_events([process_event(), network_event(), file_event()])
        process = repository.list_events("process_creation")[0]
        network = repository.list_events("network_connection")[0]
        file_row = repository.list_events("file_activity")[0]

    assert result.inserted == 3
    assert result.duplicates == 0
    assert process["process_guid"] == "{process-1}"
    assert process["command_line"] == "cmd.exe /c whoami"
    assert network["process_event_id"] == process["id"]
    assert network["destination_ip"] == "203.0.113.10"
    assert file_row["process_event_id"] == process["id"]
    assert file_row["target_filename"] == r"C:\Temp\output.txt"


def test_duplicate_insertion_is_safe_and_observable(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        first = repository.insert_events([process_event()])
        second = repository.insert_events([process_event()])

    assert first.inserted == 1
    assert second == type(second)(inserted=0, duplicates=1)


def test_transaction_rolls_back_entire_batch_on_invalid_data(tmp_path) -> None:
    invalid = network_event("bad")
    invalid.destination_port = 70000

    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        with pytest.raises(DatabaseValidationError):
            repository.insert_events([process_event(), invalid])
        assert repository.count_events() == 0


def test_retention_deletes_only_expired_events(tmp_path) -> None:
    settings = DatabaseSettings(path=tmp_path / "signaltrace.sqlite3", retention_days=30)
    old = process_event("old").model_copy(update={"timestamp": TIMESTAMP - timedelta(days=31)})
    recent = process_event("recent").model_copy(update={"timestamp": TIMESTAMP})

    with SQLiteRepository(settings) as repository:
        repository.insert_events([old, recent])
        deleted = repository.delete_expired(now=TIMESTAMP)
        remaining = repository.count_events()

    assert deleted == 1
    assert remaining == 1


def test_reopen_preserves_data(tmp_path) -> None:
    path = tmp_path / "signaltrace.sqlite3"
    with SQLiteRepository(path) as repository:
        repository.insert_events([process_event()])

    with SQLiteRepository(path) as repository:
        assert repository.count_events() == 1
        assert len(repository.list_events("process_creation")) == 1


def test_invalid_kind_is_rejected(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        with pytest.raises(DatabaseValidationError):
            repository.list_events("not-an-event")


def test_schema_uses_foreign_keys(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        assert repository.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
