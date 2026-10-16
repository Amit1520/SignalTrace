"""Tests for the one-shot Sysmon ingestion command."""

from unittest.mock import MagicMock, patch

import pytest

from backend.collector.collector import CollectionBatch, ReadOnlySysmonCollector
from backend.collector.config import SysmonCollectorSettings
from backend.collector.errors import IngestionError, IngestionErrorCode
from backend.collector.source import RawSysmonEvent, WindowsSysmonEventSource
from backend.database.repository import SQLiteRepository
from backend.ingest import run_ingestion, _count_events_by_type
from backend.normalization.models import EventKind, ProcessCreationEvent, NetworkConnectionEvent, FileActivityEvent
from backend.database.config import DatabaseSettings


class MockSource:
    """Mock Sysmon event source for testing."""
    
    def __init__(self, events: list[RawSysmonEvent]):
        self.events = events
        self.call_count = 0
    
    def read_events(self, after_record_id: str | None, limit: int):
        self.call_count += 1
        return iter(self.events)


class MockRepository:
    """Mock SQLite repository for testing."""
    
    def __init__(self):
        self.inserted = 0
        self.duplicates = 0
    
    def insert_events(self, events):
        self.inserted = len(events)
        return type('InsertionResult', (), {'inserted': self.inserted, 'duplicates': 0})()


def test_count_events_by_type():
    """Test event type counting."""
    events = [
        type('Event', (), {'kind': EventKind.PROCESS_CREATION})(),
        type('Event', (), {'kind': EventKind.PROCESS_CREATION})(),
        type('Event', (), {'kind': EventKind.NETWORK_CONNECTION})(),
        type('Event', (), {'kind': EventKind.FILE_ACTIVITY})(),
    ]
    
    counts = _count_events_by_type(events)
    
    assert counts == {
        "process_creation": 2,
        "network_connection": 1,
        "file_activity": 1,
    }


def test_run_ingestion_with_mock_source():
    """Test run_ingestion with a mock source."""
    # Create mock events
    events = [
        RawSysmonEvent(xml="<Event><System><EventID>1</EventID><EventRecordID>1</EventRecordID></System><EventData></EventData></Event>"),
        RawSysmonEvent(xml="<Event><System><EventID>3</EventID><EventRecordID>2</EventRecordID></System><EventData></EventData></Event>"),
    ]
    
    mock_source = MockSource(events)
    mock_repo = MockRepository()
    
    # We need to patch the actual classes
    with patch('backend.ingest.WindowsSysmonEventSource', return_value=mock_source), \
         patch('backend.ingest.JsonCheckpointStore'), \
         patch('backend.ingest.ReadOnlySysmonCollector') as mock_collector_class, \
         patch('backend.ingest.SQLiteRepository', return_value=mock_repo):
        
        # Configure the mock collector
        mock_batch = CollectionBatch(
            events=[
                type('Event', (), {'kind': EventKind.PROCESS_CREATION})(),
                type('Event', (), {'kind': EventKind.NETWORK_CONNECTION})(),
            ],
            errors=[],
            unsupported_events_skipped=0,
            checkpoint=type('Checkpoint', (), {'last_successful_record_id': '2'})(),
        )
        mock_collector = MagicMock()
        mock_collector.collect_once.return_value = mock_batch
        mock_collector_class.return_value = mock_collector
        
        result = run_ingestion(max_events=10)
        
        assert result["status"] == "completed"
        assert result["events_read"] == 2
        assert result["events_persisted"] == 2
        assert result["unsupported_events_skipped"] == 0
        assert result["errors"] == 0
        assert result["checkpoint_record_id"] == "2"


def test_run_ingestion_with_errors():
    """Test run_ingestion handles errors correctly."""
    events = [
        RawSysmonEvent(xml="<Event><System><EventID>1</EventID><EventRecordID>1</EventRecordID></System><EventData></EventData></Event>"),
    ]
    
    mock_source = MockSource(events)
    mock_repo = MockRepository()
    
    with patch('backend.ingest.WindowsSysmonEventSource', return_value=mock_source), \
         patch('backend.ingest.JsonCheckpointStore'), \
         patch('backend.ingest.ReadOnlySysmonCollector') as mock_collector_class, \
         patch('backend.ingest.SQLiteRepository', return_value=mock_repo):
        
        # Configure the mock collector to return errors
        mock_batch = CollectionBatch(
            events=[],
            errors=[IngestionError(code=IngestionErrorCode.MALFORMED_EVENT, message="test error")],
            unsupported_events_skipped=0,
            checkpoint=type('Checkpoint', (), {'last_successful_record_id': None})(),
        )
        mock_collector = MagicMock()
        mock_collector.collect_once.return_value = mock_batch
        mock_collector_class.return_value = mock_collector
        
        result = run_ingestion(max_events=10)
        
        assert result["status"] == "completed"
        assert result["events_read"] == 1
        assert result["events_persisted"] == 0
        assert result["errors"] == 1
        assert result["unsupported_events_skipped"] == 0


def test_run_ingestion_with_unsupported_events():
    """Test run_ingestion handles unsupported events correctly."""
    events = [
        RawSysmonEvent(xml="<Event><System><EventID>2</EventID><EventRecordID>1</EventRecordID></System><EventData></EventData></Event>"),
        RawSysmonEvent(xml="<Event><System><EventID>1</EventID><EventRecordID>2</EventRecordID></System><EventData></EventData></Event>"),
    ]
    
    mock_source = MockSource(events)
    mock_repo = MockRepository()
    
    with patch('backend.ingest.WindowsSysmonEventSource', return_value=mock_source), \
         patch('backend.ingest.JsonCheckpointStore'), \
         patch('backend.ingest.ReadOnlySysmonCollector') as mock_collector_class, \
         patch('backend.ingest.SQLiteRepository', return_value=mock_repo):
        
        # Configure the mock collector to return one unsupported event and one valid event
        mock_batch = CollectionBatch(
            events=[type('Event', (), {'kind': EventKind.PROCESS_CREATION})()],
            errors=[],
            unsupported_events_skipped=1,
            checkpoint=type('Checkpoint', (), {'last_successful_record_id': '2'})(),
        )
        mock_collector = MagicMock()
        mock_collector.collect_once.return_value = mock_batch
        mock_collector_class.return_value = mock_collector
        
        result = run_ingestion(max_events=10)
        
        assert result["status"] == "completed"
        assert result["events_read"] == 2
        assert result["events_persisted"] == 1
        assert result["unsupported_events_skipped"] == 1
        assert result["errors"] == 0
        assert result["checkpoint_record_id"] == "2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])