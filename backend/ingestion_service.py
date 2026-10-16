"""Continuous Sysmon ingestion service for SignalTrace."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.collector.checkpoint import Checkpoint, JsonCheckpointStore
from backend.collector.collector import ReadOnlySysmonCollector
from backend.collector.config import SysmonCollectorSettings
from backend.collector.source import WindowsSysmonEventSource
from backend.config import SignalTraceSettings
from backend.database.config import DatabaseSettings
from backend.database.repository import SQLiteRepository
from backend.incidents.models import Incident
from backend.pipeline import Pipeline, PipelineConfig

logger = logging.getLogger(__name__)


@dataclass
class IngestionStatus:
    """Current status of the continuous ingestion service."""

    active: bool = False
    last_ingestion_time: Optional[datetime] = None
    last_successful_collection: Optional[datetime] = None
    last_inserted_event_time: Optional[datetime] = None
    total_events_inserted: int = 0
    total_events_read: int = 0
    total_duplicates_skipped: int = 0
    total_unsupported_skipped: int = 0
    total_errors: int = 0
    last_error: Optional[str] = None
    last_error_time: Optional[datetime] = None
    current_interval_seconds: int = 10
    last_collection_duration_ms: float = 0.0
    events_in_last_collection: int = 0
    last_checkpoint_record_id: Optional[str] = None


class ContinuousIngestionService:
    """
    Continuous Sysmon ingestion service.

    A new realtime session starts from the CURRENT Sysmon EventRecordID.
    This prevents a stale checkpoint from causing the live dashboard to
    replay a large historical backlog.

    After startup, normal checkpoint semantics are preserved:

    1. Collector reads events after the current checkpoint.
    2. Collector returns a candidate checkpoint only.
    3. Events are persisted to SQLite.
    4. Candidate checkpoint is committed once after persistence.
    5. Detection/incident processing runs on genuinely inserted events.
    """

    def __init__(
        self,
        interval_seconds: int = 10,
        max_events_per_cycle: int = 100,
        settings: SignalTraceSettings | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.max_events_per_cycle = max_events_per_cycle
        self.settings = settings or SignalTraceSettings()

        self._status = IngestionStatus()
        self._status.current_interval_seconds = interval_seconds

        self._running = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    @property
    def status(self) -> IngestionStatus:
        """Return a snapshot of the current ingestion status."""
        with self._lock:
            return IngestionStatus(
                active=self._status.active,
                last_ingestion_time=self._status.last_ingestion_time,
                last_successful_collection=self._status.last_successful_collection,
                last_inserted_event_time=self._status.last_inserted_event_time,
                total_events_inserted=self._status.total_events_inserted,
                total_events_read=self._status.total_events_read,
                total_duplicates_skipped=self._status.total_duplicates_skipped,
                total_unsupported_skipped=self._status.total_unsupported_skipped,
                total_errors=self._status.total_errors,
                last_error=self._status.last_error,
                last_error_time=self._status.last_error_time,
                current_interval_seconds=self._status.current_interval_seconds,
                last_collection_duration_ms=self._status.last_collection_duration_ms,
                events_in_last_collection=self._status.events_in_last_collection,
                last_checkpoint_record_id=self._status.last_checkpoint_record_id,
            )

    def _checkpoint_path(self) -> Path:
        """Return the existing SignalTrace Sysmon checkpoint path."""
        return self.settings.checkpoint_path

    def _initialize_live_checkpoint(self) -> str:
        """
        Initialize a new realtime session from the current Sysmon position.

        This deliberately happens before the background collection thread
        starts. Therefore the first collection cycle cannot replay an old
        checkpoint backlog.

        The checkpoint is only used as the starting cursor here. Normal
        checkpoint advancement after SQLite persistence remains unchanged.
        """
        checkpoint_path = self._checkpoint_path()

        source = WindowsSysmonEventSource(
            channel="Microsoft-Windows-Sysmon/Operational"
        )

        latest_record_id = source.get_latest_record_id()

        if latest_record_id is None:
            raise RuntimeError(
                "Unable to determine the current Sysmon EventRecordID; "
                "realtime ingestion was not started."
            )

        try:
            latest_record_id_int = int(latest_record_id)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Current Sysmon EventRecordID is invalid: {latest_record_id!r}"
            ) from exc

        if latest_record_id_int < 0:
            raise RuntimeError(
                "Current Sysmon EventRecordID cannot be negative."
            )

        checkpoint_store = JsonCheckpointStore(checkpoint_path)

        checkpoint_store.save(
            Checkpoint(
                last_successful_record_id=str(latest_record_id_int)
            )
        )

        with self._lock:
            self._status.last_checkpoint_record_id = str(
                latest_record_id_int
            )
            self._status.last_error = None
            self._status.last_error_time = None

        logger.info(
            "Realtime ingestion initialized at current Sysmon "
            "EventRecordID %s",
            latest_record_id_int,
        )

        return str(latest_record_id_int)

    def start(self) -> None:
        """
        Start a new realtime ingestion session.

        Each new session intentionally starts from the current Sysmon
        position rather than resuming a potentially stale checkpoint.
        """
        with self._lock:
            if self._running:
                return

        # -------------------------------------------------------------
        # IMPORTANT:
        # Determine the current Sysmon position BEFORE starting the
        # background thread. If this fails, ingestion remains stopped.
        # -------------------------------------------------------------
        try:
            self._initialize_live_checkpoint()
        except Exception as exc:
            logger.error(
                "Unable to initialize live Sysmon checkpoint: %s",
                exc,
            )

            with self._lock:
                self._status.active = False
                self._status.last_error = str(exc)
                self._status.last_error_time = datetime.now(timezone.utc)
                self._status.total_errors += 1

            raise

        with self._lock:
            self._running = True
            self._status.active = True
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="signaltrace-sysmon-ingestion",
        )
        self._thread.start()

        logger.info(
            "Continuous realtime ingestion started with %ss interval",
            self.interval_seconds,
        )

    def stop(self) -> None:
        """Stop the continuous ingestion loop."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._status.active = False
            self._stop_event.set()

        if hasattr(self, "_thread") and self._thread.is_alive():
            self._thread.join(timeout=5.0)

        logger.info("Continuous ingestion stopped")

    def _run_loop(self) -> None:
        """Main ingestion loop running in the background thread."""
        while not self._stop_event.is_set():
            cycle_start = time.time()

            try:
                self._run_collection_cycle()
            except Exception as exc:
                logger.error(
                    "Error in ingestion cycle: %s",
                    exc,
                )

                with self._lock:
                    self._status.total_errors += 1
                    self._status.last_error = str(exc)
                    self._status.last_error_time = datetime.now(timezone.utc)

            cycle_duration = (time.time() - cycle_start) * 1000

            with self._lock:
                self._status.last_collection_duration_ms = cycle_duration

            self._stop_event.wait(self.interval_seconds)

        logger.info("Ingestion loop stopped")

    def _run_collection_cycle(self) -> None:
        """
        Execute one realtime collection + persistence + detection cycle.

        Checkpoint contract:

        1. Collector reads from the current checkpoint.
        2. Collector returns a candidate checkpoint only.
        3. Events are persisted to SQLite.
        4. Only after SQLite persistence succeeds is the candidate
           checkpoint committed once.
        5. Detection/incident processing runs on genuinely inserted events.

        The collector never performs checkpoint writes itself.
        """

        cycle_start = time.time()

        collector_settings = SysmonCollectorSettings(
            channel="Microsoft-Windows-Sysmon/Operational",
            batch_size=self.max_events_per_cycle,
            checkpoint_path=self._checkpoint_path(),
            max_xml_bytes=2_000_000,
            retention_days=None,
        )

        checkpoint_store = JsonCheckpointStore(
            collector_settings.checkpoint_path
        )

        collector = ReadOnlySysmonCollector(
            source=WindowsSysmonEventSource(
                channel=collector_settings.channel
            ),
            checkpoint_store=checkpoint_store,
            settings=collector_settings,
        )

        repository = SQLiteRepository(
            DatabaseSettings().path
        )

        try:
            # ---------------------------------------------------------
            # 1. Collect events after the current live checkpoint.
            #
            # collect_once() does NOT persist the checkpoint.
            # ---------------------------------------------------------
            batch = collector.collect_once()

            # ---------------------------------------------------------
            # 2. Persist telemetry first.
            #
            # If SQLite persistence fails, the checkpoint is NOT
            # advanced.
            # ---------------------------------------------------------
            insert_result = repository.insert_events(batch.events)
            new_events = insert_result.inserted_events

            # ---------------------------------------------------------
            # 3. Commit the candidate checkpoint exactly once.
            #
            # This happens only after telemetry has been persisted.
            # ---------------------------------------------------------
            checkpoint_error: Exception | None = None

            if batch.checkpoint.last_successful_record_id:
                try:
                    checkpoint_store.save(batch.checkpoint)

                except Exception as exc:
                    checkpoint_error = exc

                    logger.error(
                        "Checkpoint persistence failed for record %s: %s",
                        batch.checkpoint.last_successful_record_id,
                        exc,
                    )

            # ---------------------------------------------------------
            # 4. Run the SAME detection pipeline used by one-shot mode.
            #
            # Only genuinely inserted events are evaluated.
            # ---------------------------------------------------------
            pipeline = Pipeline(
                config=PipelineConfig(
                    max_events=self.max_events_per_cycle
                ),
                repository=repository,
            )

            existing_incidents = [
                Incident.model_validate(item)
                for item in repository.list_incidents()
            ]

            detection_result = pipeline.process_inserted_events(
                new_events,
                existing_incidents=existing_incidents,
            )

            # ---------------------------------------------------------
            # 5. Update ingestion metrics.
            # ---------------------------------------------------------
            now = datetime.now(timezone.utc)

            with self._lock:
                self._status.last_ingestion_time = now
                self._status.last_successful_collection = now

                self._status.total_events_read += (
                    len(batch.events)
                    + len(batch.errors)
                    + batch.unsupported_events_skipped
                )

                self._status.total_events_inserted += (
                    insert_result.inserted
                )

                self._status.total_duplicates_skipped += (
                    insert_result.duplicates
                )

                self._status.total_unsupported_skipped += (
                    batch.unsupported_events_skipped
                )

                self._status.events_in_last_collection = (
                    insert_result.inserted
                )

                if new_events:
                    self._status.last_inserted_event_time = now

                if (
                    checkpoint_error is None
                    and batch.checkpoint.last_successful_record_id
                ):
                    self._status.last_checkpoint_record_id = (
                        batch.checkpoint.last_successful_record_id
                    )

                # Collector-level errors are real ingestion errors.
                if batch.errors:
                    self._status.total_errors += len(batch.errors)
                    self._status.last_error = str(batch.errors[0])
                    self._status.last_error_time = now

                # Checkpoint persistence failure must be visible.
                if checkpoint_error is not None:
                    self._status.total_errors += 1
                    self._status.last_error = (
                        f"checkpoint persistence failed: "
                        f"{checkpoint_error}"
                    )
                    self._status.last_error_time = now

                # Detection/pipeline errors are also surfaced.
                for error in detection_result["errors"]:
                    self._status.total_errors += 1
                    self._status.last_error = error
                    self._status.last_error_time = now

                self._status.last_collection_duration_ms = (
                    time.time() - cycle_start
                ) * 1000

            if detection_result["detections_created"]:
                logger.info(
                    "Realtime detection: %d detections, %d incidents",
                    detection_result["detections_created"],
                    detection_result["incidents_created"],
                )

        finally:
            repository.close()


# ----------------------------------------------------------------------
# Global instance
# ----------------------------------------------------------------------

_ingestion_service: Optional[ContinuousIngestionService] = None


def get_ingestion_service() -> ContinuousIngestionService:
    """Get or create the global ingestion service instance."""
    global _ingestion_service

    if _ingestion_service is None:
        _ingestion_service = ContinuousIngestionService()

    return _ingestion_service


def start_continuous_ingestion(interval_seconds: int = 10) -> None:
    """Start a new realtime ingestion session."""
    service = get_ingestion_service()

    service.interval_seconds = max(1, interval_seconds)
    service._status.current_interval_seconds = service.interval_seconds

    service.start()


def stop_continuous_ingestion() -> None:
    """Stop the continuous ingestion service."""
    global _ingestion_service

    if _ingestion_service is not None:
        _ingestion_service.stop()
        _ingestion_service = None


def get_ingestion_status() -> dict:
    """Get current ingestion status as a dictionary."""
    service = get_ingestion_service()
    status = service.status

    return {
        "active": status.active,
        "last_ingestion_time": (
            status.last_ingestion_time.isoformat()
            if status.last_ingestion_time
            else None
        ),
        "last_successful_collection": (
            status.last_successful_collection.isoformat()
            if status.last_successful_collection
            else None
        ),
        "last_inserted_event_time": (
            status.last_inserted_event_time.isoformat()
            if status.last_inserted_event_time
            else None
        ),
        "total_events_inserted": status.total_events_inserted,
        "total_events_read": status.total_events_read,
        "total_duplicates_skipped": status.total_duplicates_skipped,
        "total_unsupported_skipped": status.total_unsupported_skipped,
        "total_errors": status.total_errors,
        "last_error": status.last_error,
        "last_error_time": (
            status.last_error_time.isoformat()
            if status.last_error_time
            else None
        ),
        "current_interval_seconds": status.current_interval_seconds,
        "last_collection_duration_ms": status.last_collection_duration_ms,
        "events_in_last_collection": status.events_in_last_collection,
        "last_checkpoint_record_id": status.last_checkpoint_record_id,
    }