"""One-shot real Windows Sysmon ingestion command for SignalTrace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from backend.collector.collector import ReadOnlySysmonCollector
from backend.collector.config import SysmonCollectorSettings
from backend.collector.source import WindowsSysmonEventSource
from backend.collector.checkpoint import JsonCheckpointStore
from backend.config import SignalTraceSettings
from backend.database.repository import SQLiteRepository


def run_ingestion(
    max_events: int | None = None,
    settings: SignalTraceSettings | None = None,
) -> dict[str, object]:
    """
    Run a one-shot real Windows Sysmon ingestion.

    Args:
        max_events: Maximum number of events to read (overrides batch_size if set)
        settings: SignalTrace settings (uses defaults if not provided)

    Returns:
        Dictionary with ingestion summary
    """
    settings = settings or SignalTraceSettings()

    # Create components
    source = WindowsSysmonEventSource(channel=settings.sysmon_channel)
    checkpoint_store = JsonCheckpointStore(settings.checkpoint_path)
    collector_settings = SysmonCollectorSettings(
        channel=settings.sysmon_channel,
        batch_size=max_events or settings.sysmon_batch_size,
        checkpoint_path=settings.checkpoint_path,
        max_xml_bytes=settings.sysmon_max_xml_bytes,
        retention_days=settings.retention_days,
    )
    collector = ReadOnlySysmonCollector(
        source=source,
        checkpoint_store=JsonCheckpointStore(settings.checkpoint_path),
        settings=collector_settings,
    )
    repository = SQLiteRepository(settings.database_settings())

    # Collect events
    batch = collector.collect_once()

    # Persist events
    result = repository.insert_events(batch.events)

    # Prepare summary
    return {
        "status": "completed",
        "events_read": len(batch.events) + len(batch.errors) + batch.unsupported_events_skipped,
        "events_persisted": result.inserted,
        "unsupported_events_skipped": batch.unsupported_events_skipped,
        "duplicates_skipped": result.duplicates,
        "errors": len(batch.errors),
        "checkpoint_record_id": batch.checkpoint.last_successful_record_id,
        "events_by_type": _count_events_by_type(batch.events),
    }


def _count_events_by_type(events: list) -> dict[str, int]:
    """Count events by their kind."""
    counts = {}
    for event in events:
        kind = event.kind.value
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def main() -> int:
    """CLI entry point for one-shot Sysmon ingestion."""
    parser = argparse.ArgumentParser(
        description="One-shot real Windows Sysmon ingestion for SignalTrace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m backend.ingest
  python -m backend.ingest --max-events 100
  SIGNALTRACE_DATABASE_PATH=data/signaltrace.sqlite3 python -m backend.ingest --max-events 50
        """,
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum number of events to read (overrides batch_size)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to .env file (optional, uses environment variables by default)",
    )

    args = parser.parse_args()

    # Load .env file if specified
    if args.config:
        from dotenv import load_dotenv
        load_dotenv(args.config)

    try:
        result = run_ingestion(max_events=args.max_events)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as e:
        print(json.dumps({"status": "failed", "error": str(e)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    import json
    sys.exit(main())