from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from backend.baseline.builder import BaselineBuilder, BaselineSettings
from backend.collector.checkpoint import JsonCheckpointStore
from backend.collector.collector import ReadOnlySysmonCollector
from backend.collector.config import SysmonCollectorSettings
from backend.collector.source import WindowsSysmonEventSource
from backend.database.config import DatabaseSettings
from backend.database.repository import SQLiteRepository
from backend.detection.detector import StatisticalDetector
from backend.detection.engine import BehavioralDetector, DetectionConfig
from backend.detection.vector import observation_from_row
from backend.features.extractor import normalize_executable_path
from backend.incidents.correlator import CorrelationConfig, IncidentCorrelator
from backend.incidents.models import Incident


@dataclass(frozen=True)
class PipelineConfig:
    """
    Configuration for one-shot SignalTrace telemetry orchestration.

    The pipeline performs exactly one collection pass.
    """

    max_events: int = 100

    min_profile_observations: int = 5
    min_statistical_observations: int = 10

    correlation_window_minutes: int = 10
    min_anomalies_for_incident: int = 2
    min_categories_for_incident: int = 2


@dataclass
class PipelineResult:
    status: str = "not_started"

    events_read: int = 0
    events_inserted: int = 0
    duplicates: int = 0

    events_by_type: dict[str, int] = field(default_factory=dict)

    detections_created: int = 0
    incidents_created: int = 0
    incident_ids: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    checkpoint: Any | None = None

    status_detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "events_read": self.events_read,
            "events_inserted": self.events_inserted,
            "duplicates": self.duplicates,
            "events_by_type": dict(self.events_by_type),
            "detections_created": self.detections_created,
            "incidents_created": self.incidents_created,
            "incident_ids": list(self.incident_ids),
            "errors": list(self.errors),
            "checkpoint": self.checkpoint,
            "status_detail": dict(self.status_detail),
        }


class Pipeline:
    """
    One-shot SignalTrace telemetry orchestration.

    Processing order:

        existing telemetry
            ↓
        existing baseline + statistical model
            ↓
        collect NEW Sysmon telemetry
            ↓
        persist NEW telemetry
            ↓
        detect ONLY insertion_result.inserted_events
            ↓
        persist detections
            ↓
        correlate complete detection batch
            ↓
        persist incidents

    Newly inserted telemetry is never used to build or rebuild the
    baseline before detection.
    """

    def __init__(
        self,
        config: PipelineConfig | None = None,
        repository: SQLiteRepository | None = None,
        collector: ReadOnlySysmonCollector | None = None,
    ) -> None:
        self.config = config or PipelineConfig()
        self.repository = repository
        self.collector = collector

    def run(self) -> PipelineResult:
        result = PipelineResult(status="started")

        repository = self.repository
        collector = self.collector

        close_repository = False

        try:
            # =========================================================
            # 1. Existing database
            # =========================================================
            if repository is None:
                repository = SQLiteRepository(DatabaseSettings())
                close_repository = True

            # Keep the repository available to the reusable detection
            # stage when Pipeline.run() created it internally.
            self.repository = repository

            # =========================================================
            # 2. Existing Sysmon collector configuration
            # =========================================================
            if collector is None:
                collector_settings = SysmonCollectorSettings(
                    batch_size=self.config.max_events,
                )

                source = WindowsSysmonEventSource(
                    channel=collector_settings.channel,
                )

                checkpoint_store = JsonCheckpointStore(
                    collector_settings.checkpoint_path,
                )

                collector = ReadOnlySysmonCollector(
                    source=source,
                    checkpoint_store=checkpoint_store,
                    settings=collector_settings,
                )

            # =========================================================
            # 3. ONE read-only Sysmon collection
            # =========================================================
            batch = collector.collect_once()

            result.events_read = len(batch.events)
            result.checkpoint = getattr(batch, "checkpoint", None)

            # Record collection-level errors without aborting the
            # entire pipeline.
            for error in getattr(batch, "errors", []):
                result.errors.append(
                    f"{type(error).__name__}: {error}"
                )

            # Unsupported events are intentionally skipped by the
            # collector and therefore are not treated as detections.
            unsupported_count = getattr(
                batch,
                "unsupported_events_skipped",
                0,
            )

            if unsupported_count:
                result.status_detail["unsupported_events_skipped"] = (
                    unsupported_count
                )

            # =========================================================
            # 4. Count collected event types
            # =========================================================
            for event in batch.events:
                try:
                    kind = self._event_kind(event)

                    result.events_by_type[kind] = (
                        result.events_by_type.get(kind, 0) + 1
                    )

                except Exception as exc:
                    result.errors.append(
                        "unable to determine event kind: "
                        f"{type(exc).__name__}: {exc}"
                    )

            # =========================================================
            # 5. No events
            # =========================================================
            if not batch.events:
                if result.errors:
                    result.status = "completed_with_errors"
                    result.status_detail["message"] = (
                        "one-shot telemetry collection completed "
                        "with collection errors"
                    )
                else:
                    result.status = "ok"
                    result.status_detail["message"] = (
                        "no telemetry events collected"
                    )

                return result

            # =========================================================
            # 6. Persist collected telemetry
            # =========================================================
            insertion_result = repository.insert_events(
                batch.events
            )

            result.events_inserted = insertion_result.inserted
            result.duplicates = insertion_result.duplicates

            # CRITICAL PHASE 11 RULE:
            #
            # Detection MUST operate only on events genuinely inserted
            # during this execution.
            #
            # Never call repository.list_events() to rediscover them.
            # =========================================================
            new_events = insertion_result.inserted_events

            if not new_events:
                result.status = (
                    "completed_with_errors"
                    if result.errors
                    else "ok"
                )

                result.status_detail["message"] = (
                    "telemetry collected but all events "
                    "were duplicates"
                )

                return result

            # =========================================================
            # 7. Process ONLY genuinely inserted events through the
            #    existing SignalTrace detection + incident pipeline.
            # =========================================================
            detection_result = self.process_inserted_events(
                new_events,
                existing_incidents=None,
            )

            result.detections_created = detection_result["detections_created"]
            result.incidents_created = detection_result["incidents_created"]
            result.incident_ids.extend(detection_result["incident_ids"])
            result.status_detail.update(detection_result["status_detail"])
            result.errors.extend(detection_result["errors"])

            # =========================================================
            # 8. Final pipeline status
            # =========================================================
            if result.errors:
                result.status = "completed_with_errors"
            else:
                result.status = "ok"

            result.status_detail.setdefault(
                "message",
                "one-shot telemetry pipeline completed",
            )

            return result

        except Exception as exc:
            result.status = "failed"

            result.errors.append(
                f"{type(exc).__name__}: {exc}"
            )

            result.status_detail["message"] = (
                "one-shot telemetry pipeline failed"
            )

            return result

        finally:
            if close_repository and repository is not None:
                try:
                    repository.close()
                except Exception as exc:
                    result.errors.append(
                        "repository close failed: "
                        f"{type(exc).__name__}: {exc}"
                    )

    def process_inserted_events(
        self,
        new_events: list[Any],
        existing_incidents: list[Incident] | None = None,
    ) -> dict[str, Any]:
        """
        Run the existing SignalTrace detection/correlation pipeline on
        events that were genuinely inserted into the database.

        This method deliberately does NOT rebuild the baseline. It loads
        the existing profile/model and evaluates only ``new_events``.
        Both one-shot and continuous ingestion use this same method so
        detection behavior stays identical across modes.
        """
        result: dict[str, Any] = {
            "detections_created": 0,
            "incidents_created": 0,
            "incident_ids": [],
            "errors": [],
            "status_detail": {},
        }

        if not new_events:
            return result

        grouping_result = PipelineResult()
        events_by_application = self._group_new_events_by_app(
            new_events,
            grouping_result,
        )
        result["errors"].extend(grouping_result.errors)

        behavioral_detector = BehavioralDetector(
            DetectionConfig(
                minimum_profile_observations=self.config.min_profile_observations
            )
        )

        detections = []

        baseline_builder = BaselineBuilder(
            self.repository,
            BaselineSettings(
                minimum_observations=self.config.min_profile_observations
            ),
        )

        for application_identity, application_events in events_by_application.items():
            try:
                canonical_identity = normalize_executable_path(
                    application_identity
                )

                if not canonical_identity:
                    result["errors"].append(
                        "unable to canonicalize application identity: "
                        f"{application_identity!r}"
                    )
                    continue

                profile = baseline_builder.load(canonical_identity)

                if profile is None:
                    profile = baseline_builder.build(canonical_identity)

                if profile is None:
                    result["status_detail"].setdefault(
                        "baseline_unavailable", []
                    ).append(canonical_identity)
                    continue

                statistical_detector = StatisticalDetector.load(
                    self.repository,
                    canonical_identity,
                    profile.profile_version,
                )

                for event in application_events:
                    try:
                        kind = self._event_kind(event)
                        row = self._event_to_row(event)
                        observation = observation_from_row(
                            kind,
                            row,
                            profile,
                        )

                        outcome = behavioral_detector.detect(
                            observation,
                            profile,
                            statistical_detector,
                        )

                        if outcome.result is None:
                            if outcome.insufficient_baseline:
                                result["status_detail"].setdefault(
                                    "insufficient_baseline", []
                                ).append(canonical_identity)
                            continue

                        detection = outcome.result
                        self.repository.save_detection(
                            detection,
                            detection.contributing_signals,
                        )
                        detections.append(detection)
                        result["detections_created"] += 1

                    except Exception as exc:
                        result["errors"].append(
                            f"{canonical_identity}: "
                            f"{type(exc).__name__}: {exc}"
                        )

            except Exception as exc:
                result["errors"].append(
                    f"{application_identity}: "
                    f"{type(exc).__name__}: {exc}"
                )

        if detections:
            correlation_config = CorrelationConfig(
                correlation_window=timedelta(
                    minutes=self.config.correlation_window_minutes
                ),
                minimum_anomalies=self.config.min_anomalies_for_incident,
                minimum_categories=self.config.min_categories_for_incident,
            )

            correlator = IncidentCorrelator(correlation_config)
            incidents = correlator.correlate(
                detections,
                existing=existing_incidents or [],
            )

            for incident in incidents:
                try:
                    self.repository.save_incident(incident)
                    result["incidents_created"] += 1
                    result["incident_ids"].append(incident.incident_id)
                except Exception as exc:
                    result["errors"].append(
                        "incident persistence failed: "
                        f"{type(exc).__name__}: {exc}"
                    )

        return result



    # =================================================================
    # Helper methods
    # =================================================================

    @staticmethod
    def _group_new_events_by_app(
        events: list[Any],
        result: PipelineResult,
    ) -> dict[str, list[Any]]:
        grouped: dict[str, list[Any]] = defaultdict(list)

        for event in events:
            try:
                image = getattr(event, "image", None)

                if not image:
                    result.errors.append(
                        "new telemetry event has no application image"
                    )
                    continue

                identity = normalize_executable_path(
                    image
                )

                if not identity:
                    result.errors.append(
                        "unable to normalize application image: "
                        f"{image!r}"
                    )
                    continue

                grouped[identity].append(event)

            except Exception as exc:
                result.errors.append(
                    "unable to group telemetry event: "
                    f"{type(exc).__name__}: {exc}"
                )

        return dict(grouped)

    @staticmethod
    def _event_kind(event: Any) -> str:
        """
        Convert normalized event models into the event-kind identifiers
        already used by SignalTrace.
        """

        event_name = type(event).__name__

        mapping = {
            "ProcessCreationEvent": "process_creation",
            "NetworkConnectionEvent": "network_connection",
            "FileActivityEvent": "file_activity",
        }

        if event_name in mapping:
            return mapping[event_name]

        explicit_kind = getattr(
            event,
            "kind",
            None,
        )

        if explicit_kind:
            return str(explicit_kind)

        raise ValueError(
            "unsupported telemetry event type: "
            f"{event_name}"
        )

    @staticmethod
    def _event_to_row(
        event: Any,
    ) -> dict[str, Any]:
        """
        Convert a normalized event model to the row-like mapping
        expected by observation_from_row().
        """

        if hasattr(event, "model_dump"):
            row = event.model_dump(
                mode="python"
            )

        elif hasattr(event, "__dict__"):
            row = dict(
                vars(event)
            )

        else:
            raise TypeError(
                "unsupported event representation: "
                f"{type(event).__name__}"
            )

        image = row.get("image")

        if image:
            row["image_path"] = (
                normalize_executable_path(image)
            )

        return row

def run_pipeline(
    max_events: int | None = None,
) -> PipelineResult:
    """
    Public one-shot pipeline entry point.
    """

    config = PipelineConfig()

    if max_events is not None:
        config = PipelineConfig(
            max_events=max_events
        )

    return Pipeline(
        config=config
    ).run()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run one-shot SignalTrace Windows "
            "Sysmon telemetry processing."
        )
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=100,
        help=(
            "Maximum number of Sysmon events "
            "to collect in this execution."
        ),
    )

    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    result = run_pipeline(
        max_events=args.max_events
    )

    print(
        json.dumps(
            result.to_dict(),
            indent=2,
            default=str,
        )
    )

    return (
        0
        if result.status != "failed"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )