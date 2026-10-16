from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterable




from backend.normalization.models import (
    FileActivityEvent,
    NetworkConnectionEvent,
    NormalizedEvent,
    ProcessCreationEvent,
)

if TYPE_CHECKING:
    from backend.features.models import SignalTraceProfile

from .config import DatabaseSettings
from .errors import DatabaseValidationError
from .schema import SCHEMA_STATEMENTS


@dataclass(frozen=True)
class InsertionResult:
    inserted: int
    duplicates: int
    inserted_events: list[NormalizedEvent] = field(default_factory=list)


class SQLiteRepository:
    def __init__(
        self,
        settings: DatabaseSettings | Path,
        *,
        repair_incident_timestamps: bool = False,
    ) -> None:
        self.settings = (
            settings
            if isinstance(settings, DatabaseSettings)
            else DatabaseSettings(path=settings)
        )
        self.path = self.settings.resolved_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            self.path,
            timeout=30.0,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.initialize(repair_incident_timestamps=repair_incident_timestamps)

    def initialize(self, *, repair_incident_timestamps: bool = False) -> None:
        with self.connection:
            for statement in SCHEMA_STATEMENTS:
                self.connection.execute(statement)

            # Add missing columns to existing anomalies table if they don't exist
            self._ensure_anomalies_columns_exist()

            # Historical repair is intentionally opt-in.
            # Normal API repository construction must not perform this
            # potentially expensive write operation.
            if repair_incident_timestamps:
                self._repair_incident_timestamps()
    
    def _ensure_anomalies_columns_exist(self) -> None:
        """Add missing columns to existing anomalies table for backward compatibility."""
        columns_to_check = [
            ("host", "TEXT"),
            ("process_guid", "TEXT"),
            ("parent_process_guid", "TEXT"),
            ("process_id", "INTEGER"),
            ("image_path", "TEXT"),
            ("model_version", "TEXT"),
            ("baseline_observation_count", "INTEGER"),
        ]
        
        for column_name, column_type in columns_to_check:
            try:
                # Check if column exists by trying to read from it
                self.connection.execute(f"SELECT {column_name} FROM anomalies LIMIT 1")
            except sqlite3.OperationalError:
                # Column doesn't exist, add it
                self.connection.execute(
                    f"ALTER TABLE anomalies ADD COLUMN {column_name} {column_type}"
                )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "SQLiteRepository":
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    # =================================================================
    # TELEMETRY WRITE
    # =================================================================

    def insert_events(
        self,
        events: Iterable[NormalizedEvent],
    ) -> InsertionResult:
        event_list = list(events)
        self._validate_events(event_list)

        inserted = 0
        duplicates = 0
        inserted_events: list[NormalizedEvent] = []

        with self.connection:
            for event in event_list:
                event_key = _event_key(event)

                existing = self.connection.execute(
                    "SELECT id FROM ingestion_events WHERE event_key = ?",
                    (event_key,),
                ).fetchone()

                if existing is not None:
                    duplicates += 1
                    continue

                ingestion_id = self._insert_ingestion_event(
                    event,
                    event_key,
                )

                if isinstance(event, ProcessCreationEvent):
                    self._insert_process_event(
                        ingestion_id,
                        event,
                    )
                elif isinstance(event, NetworkConnectionEvent):
                    self._insert_network_event(
                        ingestion_id,
                        event,
                    )
                elif isinstance(event, FileActivityEvent):
                    self._insert_file_event(
                        ingestion_id,
                        event,
                    )

                inserted += 1
                inserted_events.append(event)

        return InsertionResult(
            inserted=inserted,
            duplicates=duplicates,
            inserted_events=inserted_events,
        )

    # =================================================================
    # TELEMETRY READ
    # =================================================================

    def list_events(self, kind: str) -> list[sqlite3.Row]:
        table = {
            "process_creation": "process_events",
            "network_connection": "network_events",
            "file_activity": "file_events",
        }.get(kind)

        if table is None:
            raise DatabaseValidationError(
                f"unsupported event kind: {kind}"
            )

        return list(
            self.connection.execute(
                f"SELECT * FROM {table} ORDER BY timestamp, id"
            )
        )

    def count_events(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM ingestion_events"
        ).fetchone()

        return int(row["count"])

    def list_recent_events(
        self,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        """
        Return recent normalized telemetry as one unified list.

        The database stores process, network, and file telemetry in
        separate detail tables. This method joins those records back
        to ingestion_events and exposes a dashboard-friendly shape.
        """

        if limit <= 0:
            return []

        limit = min(limit, 1000)

        rows = self.connection.execute(
            """
            SELECT
                ingestion_events.id AS ingestion_id,
                ingestion_events.event_key,
                ingestion_events.event_kind,
                ingestion_events.source,
                ingestion_events.channel,
                ingestion_events.host,
                ingestion_events.record_id,
                ingestion_events.event_id,
                ingestion_events.timestamp,

                process_events.process_guid AS process_process_guid,
                process_events.process_id AS process_process_id,
                process_events.parent_process_guid
                    AS process_parent_process_guid,
                process_events.parent_process_id
                    AS process_parent_process_id,
                process_events.parent_image
                    AS process_parent_image,
                process_events.image_path
                    AS process_image_path,
                process_events.command_line
                    AS process_command_line,
                process_events.hashes_json
                    AS process_hashes_json,
                process_events.current_directory
                    AS process_current_directory,
                process_events.user_name
                    AS process_user_name,
                process_events.integrity_level
                    AS process_integrity_level,

                network_events.process_guid
                    AS network_process_guid,
                network_events.process_id
                    AS network_process_id,
                network_events.image_path
                    AS network_image_path,
                network_events.command_line
                    AS network_command_line,
                network_events.hashes_json
                    AS network_hashes_json,
                network_events.protocol,
                network_events.initiated,
                network_events.source_ip,
                network_events.source_port,
                network_events.destination_ip,
                network_events.destination_hostname,
                network_events.destination_port,

                file_events.process_guid
                    AS file_process_guid,
                file_events.process_id
                    AS file_process_id,
                file_events.image_path
                    AS file_image_path,
                file_events.command_line
                    AS file_command_line,
                file_events.hashes_json
                    AS file_hashes_json,
                file_events.target_filename,
                file_events.creation_utc

            FROM ingestion_events

            LEFT JOIN process_events
                ON process_events.ingestion_event_id =
                   ingestion_events.id

            LEFT JOIN network_events
                ON network_events.ingestion_event_id =
                   ingestion_events.id

            LEFT JOIN file_events
                ON file_events.ingestion_event_id =
                   ingestion_events.id

            ORDER BY
                ingestion_events.timestamp DESC,
                ingestion_events.id DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        events: list[dict[str, object]] = []

        for row in rows:
            kind = row["event_kind"]

            event: dict[str, object] = {
                "id": row["ingestion_id"],
                "event_key": row["event_key"],
                "kind": kind,
                "source": row["source"],
                "channel": row["channel"],
                "host": row["host"],
                "record_id": row["record_id"],
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
            }

            if kind == "process_creation":
                event.update(
                    {
                        "process_guid": row["process_process_guid"],
                        "process_id": row["process_process_id"],
                        "parent_process_guid": (
                            row["process_parent_process_guid"]
                        ),
                        "parent_process_id": (
                            row["process_parent_process_id"]
                        ),
                        "parent_image": row["process_parent_image"],
                        "image": row["process_image_path"],
                        "application_identity": (
                            row["process_image_path"]
                        ),
                        "command_line": row["process_command_line"],
                        "hashes": _loads_json(
                            row["process_hashes_json"],
                            {},
                        ),
                        "current_directory": (
                            row["process_current_directory"]
                        ),
                        "user": row["process_user_name"],
                        "integrity_level": (
                            row["process_integrity_level"]
                        ),
                    }
                )

            elif kind == "network_connection":
                event.update(
                    {
                        "process_guid": row["network_process_guid"],
                        "process_id": row["network_process_id"],
                        "image": row["network_image_path"],
                        "application_identity": (
                            row["network_image_path"]
                        ),
                        "command_line": row["network_command_line"],
                        "hashes": _loads_json(
                            row["network_hashes_json"],
                            {},
                        ),
                        "protocol": row["protocol"],
                        "initiated": (
                            None
                            if row["initiated"] is None
                            else bool(row["initiated"])
                        ),
                        "source_ip": row["source_ip"],
                        "source_port": row["source_port"],
                        "destination_ip": row["destination_ip"],
                        "destination_hostname": (
                            row["destination_hostname"]
                        ),
                        "destination_port": row["destination_port"],
                    }
                )

            elif kind == "file_activity":
                event.update(
                    {
                        "process_guid": row["file_process_guid"],
                        "process_id": row["file_process_id"],
                        "image": row["file_image_path"],
                        "application_identity": (
                            row["file_image_path"]
                        ),
                        "command_line": row["file_command_line"],
                        "hashes": _loads_json(
                            row["file_hashes_json"],
                            {},
                        ),
                        "target_filename": row["target_filename"],
                        "creation_utc": row["creation_utc"],
                    }
                )

            events.append(event)

        return events

        # =================================================================
    # APPLICATIONS
    # =================================================================

    def list_applications(self) -> list[dict[str, object]]:
        """
        Return every application observed by normalized telemetry.

        The latest behavioral profile is included when one exists.
        Application identities are normalized before looking up their
        behavioral profiles so Windows path formatting differences do
        not prevent profile association.
        """
        rows = self.connection.execute(
            """
            SELECT
                applications.id,
                applications.image_path,
                applications.first_seen_at,
                applications.last_seen_at,

                (
                    SELECT COUNT(*)
                    FROM ingestion_events ie
                    LEFT JOIN process_events pe
                        ON pe.ingestion_event_id = ie.id
                    LEFT JOIN network_events ne
                        ON ne.ingestion_event_id = ie.id
                    LEFT JOIN file_events fe
                        ON fe.ingestion_event_id = ie.id
                    WHERE
                        pe.application_id = applications.id
                        OR ne.application_id = applications.id
                        OR fe.application_id = applications.id
                ) AS observed_event_count

            FROM applications

            ORDER BY
                applications.last_seen_at DESC,
                applications.image_path ASC
            """
        ).fetchall()

        applications: list[dict[str, object]] = []

        for row in rows:
            application_identity = row["image_path"]

            from backend.features.extractor import normalize_executable_path

            canonical_identity = normalize_executable_path(
                application_identity
            )

            # Look up the latest profile using the canonical identity.
            profile_row = self.connection.execute(
                """
                SELECT
                    profile_version,
                    observation_start,
                    observation_end,
                    observation_count,
                    profile_status,
                    profile_json
                FROM behavior_profiles
                WHERE application_identity = ?
                ORDER BY profile_version DESC
                LIMIT 1
                """,
                (canonical_identity,),
            ).fetchone()

            profile = None

            if profile_row is not None:
                profile = _loads_json(
                    profile_row["profile_json"],
                    None,
                )

            applications.append(
                {
                    "id": row["id"],
                    "application_identity": application_identity,
                    "first_seen": row["first_seen_at"],
                    "last_seen": row["last_seen_at"],
                    "observation_count": (
                        row["observed_event_count"] or 0
                    ),
                    "profile_version": (
                        profile_row["profile_version"]
                        if profile_row is not None
                        else None
                    ),
                    "observation_start": (
                        profile_row["observation_start"]
                        if profile_row is not None
                        else None
                    ),
                    "observation_end": (
                        profile_row["observation_end"]
                        if profile_row is not None
                        else None
                    ),
                    "profile_observation_count": (
                        profile_row["observation_count"] or 0
                        if profile_row is not None
                        else 0
                    ),
                    "profile_status": (
                        profile_row["profile_status"] or "not_built"
                        if profile_row is not None
                        else "not_built"
                    ),
                    "profile": profile,
                }
            )

        return applications

    def count_applications(self) -> int:
        row = self.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM applications
            """
        ).fetchone()

        return int(row["count"])


    # =================================================================
    # PROFILES
    # =================================================================

    def next_profile_version(
        self,
        application_identity: str,
    ) -> int:
        row = self.connection.execute(
            """
            SELECT COALESCE(MAX(profile_version), 0) AS version
            FROM behavior_profiles
            WHERE application_identity = ?
            """,
            (application_identity,),
        ).fetchone()

        return int(row["version"]) + 1

    def save_profile(
        self,
        profile: "SignalTraceProfile",
    ) -> None:
        payload = profile.model_dump(mode="json")

        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO behavior_profiles
                (
                    application_identity,
                    profile_version,
                    observation_start,
                    observation_end,
                    observation_count,
                    profile_status,
                    profile_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.application_identity,
                    profile.profile_version,
                    _timestamp(profile.observation_start),
                    _timestamp(profile.observation_end),
                    profile.observation_count,
                    profile.profile_status,
                    json.dumps(payload, sort_keys=True),
                ),
            )

            profile_id = int(cursor.lastrowid)

            for category, values in _profile_categories(profile).items():
                for key, value in sorted(values.items()):
                    self.connection.execute(
                        """
                        INSERT INTO behavior_features
                        (
                            profile_id,
                            feature_category,
                            feature_key,
                            feature_value_json
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            profile_id,
                            category,
                            key,
                            json.dumps(
                                value,
                                sort_keys=True,
                                default=_json_default,
                            ),
                        ),
                    )

    def load_profile(
        self,
        application_identity: str,
        version: int | None = None,
    ) -> "SignalTraceProfile | None":
        from backend.features.models import SignalTraceProfile

        if version is None:
            row = self.connection.execute(
                """
                SELECT profile_json
                FROM behavior_profiles
                WHERE application_identity = ?
                ORDER BY profile_version DESC
                LIMIT 1
                """,
                (application_identity,),
            ).fetchone()
        else:
            row = self.connection.execute(
                """
                SELECT profile_json
                FROM behavior_profiles
                WHERE application_identity = ?
                  AND profile_version = ?
                """,
                (application_identity, version),
            ).fetchone()

        return (
            SignalTraceProfile.model_validate(
                json.loads(row["profile_json"])
            )
            if row
            else None
        )

    # =================================================================
    # DETECTOR MODEL
    # =================================================================

    def save_detector_model(
        self,
        application_identity: str,
        profile_version: int,
        model_version: str,
        feature_schema_version: str,
        metadata: dict[str, object],
        model_blob: bytes,
    ) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT OR REPLACE INTO detector_models
                (
                    application_identity,
                    profile_version,
                    model_version,
                    feature_schema_version,
                    metadata_json,
                    model_blob
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    application_identity,
                    profile_version,
                    model_version,
                    feature_schema_version,
                    json.dumps(metadata, sort_keys=True),
                    model_blob,
                ),
            )

    def load_detector_model(
        self,
        application_identity: str,
        profile_version: int,
    ) -> dict[str, object] | None:
        row = self.connection.execute(
            """
            SELECT
                model_version,
                feature_schema_version,
                metadata_json,
                model_blob
            FROM detector_models
            WHERE application_identity = ?
              AND profile_version = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                application_identity,
                profile_version,
            ),
        ).fetchone()

        if row is None:
            return None

        return {
            "model_version": row["model_version"],
            "feature_schema_version": row["feature_schema_version"],
            "metadata": json.loads(row["metadata_json"]),
            "model_blob": row["model_blob"],
        }

    # =================================================================
    # DETECTIONS
    # =================================================================

    def save_detection(
        self,
        result,
        signals: list[object],
    ) -> None:
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO anomalies
                (
                    detection_id,
                    application_identity,
                    timestamp,
                    anomaly_score,
                    severity,
                    confidence,
                    statistical_contribution,
                    deterministic_contribution,
                    profile_version,
                    detector_version,
                    feature_schema_version,
                    reason,
                    provenance_json,
                    host,
                    process_guid,
                    parent_process_guid,
                    process_id,
                    image_path,
                    model_version,
                    baseline_observation_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.detection_id,
                    result.application_identity,
                    _timestamp(result.timestamp),
                    result.anomaly_score,
                    result.severity.value,
                    result.confidence,
                    result.statistical_contribution,
                    result.deterministic_contribution,
                    result.baseline_comparison.profile_version,
                    result.detector_version,
                    result.feature_schema_version,
                    result.reason,
                    json.dumps(
                        result.provenance_references,
                        sort_keys=True,
                    ),
                    result.host,
                    result.process_guid,
                    result.parent_process_guid,
                    result.process_id,
                    result.image_path,
                    result.model_version,
                    result.baseline_comparison.observation_count,
                ),
            )

            anomaly_id = int(cursor.lastrowid)

            for signal in signals:
                self.connection.execute(
                    """
                    INSERT INTO detection_signals
                    (
                        anomaly_id,
                        category,
                        signal_type,
                        observed_value_json,
                        baseline_value_json,
                        deviation,
                        weight,
                        contribution,
                        evidence_reference
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        anomaly_id,
                        signal.category.value,
                        signal.signal_type,
                        json.dumps(
                            signal.observed_value,
                            sort_keys=True,
                            default=_json_default,
                        ),
                        json.dumps(
                            signal.baseline_value,
                            sort_keys=True,
                            default=_json_default,
                        ),
                        signal.deviation,
                        signal.weight,
                        signal.contribution,
                        signal.evidence_reference,
                    ),
                )

    def list_detections(
        self,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        """
        Return persisted behavioral detections with their signals.
        """

        if limit <= 0:
            return []

        limit = min(limit, 1000)

        rows = self.connection.execute(
            """
            SELECT
                id,
                detection_id,
                application_identity,
                timestamp,
                anomaly_score,
                severity,
                confidence,
                statistical_contribution,
                deterministic_contribution,
                profile_version,
                detector_version,
                feature_schema_version,
                reason,
                provenance_json,
                host,
                process_guid,
                parent_process_guid,
                process_id,
                image_path,
                model_version,
                baseline_observation_count

            FROM anomalies

            ORDER BY
                timestamp DESC,
                id DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        detections: list[dict[str, object]] = []

        for row in rows:
            signal_rows = self.connection.execute(
                """
                SELECT
                    category,
                    signal_type,
                    observed_value_json,
                    baseline_value_json,
                    deviation,
                    weight,
                    contribution,
                    evidence_reference

                FROM detection_signals

                WHERE anomaly_id = ?

                ORDER BY
                    contribution DESC,
                    id ASC
                """,
                (row["id"],),
            ).fetchall()

            signals: list[dict[str, object]] = []

            for signal_row in signal_rows:
                signals.append(
                    {
                        "category": signal_row["category"],
                        "signal_type": signal_row["signal_type"],
                        "observed_value": _loads_json(
                            signal_row["observed_value_json"],
                            None,
                        ),
                        "baseline_value": _loads_json(
                            signal_row["baseline_value_json"],
                            None,
                        ),
                        "deviation": signal_row["deviation"],
                        "weight": signal_row["weight"],
                        "contribution": signal_row["contribution"],
                        "evidence_reference": (
                            signal_row["evidence_reference"]
                        ),
                    }
                )

            provenance = _loads_json(
                row["provenance_json"],
                [],
            )

            detections.append(
                {
                    "detection_id": row["detection_id"],
                    "application_identity": (
                        row["application_identity"]
                    ),
                    "timestamp": row["timestamp"],
                    "anomaly_score": row["anomaly_score"],
                    "severity": row["severity"],
                    "confidence": row["confidence"],
                    "statistical_contribution": (
                        row["statistical_contribution"]
                    ),
                    "deterministic_contribution": (
                        row["deterministic_contribution"]
                    ),
                    "contributing_signals": signals,
                    "baseline_comparison": {
                        "profile_version": row["profile_version"],
                        "profile_status": "available",
                        "feature_schema_version": (
                            row["feature_schema_version"]
                        ),
                        "observation_count": row["baseline_observation_count"],
                        "compatible": True,
                    },
                    "provenance_references": provenance,
                    "detector_version": row["detector_version"],
                    "model_version": row["model_version"],
                    "feature_schema_version": (
                        row["feature_schema_version"]
                    ),
                    "reason": row["reason"],
                    "host": row["host"],
                    "process_guid": row["process_guid"],
                    "parent_process_guid": row["parent_process_guid"],
                    "process_id": row["process_id"],
                    "image_path": row["image_path"],
                }
            )

        return detections

    def count_detections(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM anomalies"
        ).fetchone()

        return int(row["count"])

    def count_behavioral_deviations(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM anomalies WHERE severity != 'normal'"
        ).fetchone()

        return int(row["count"])

    def count_incidents(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM incidents"
        ).fetchone()

        return int(row["count"])

    def count_unresolved_incidents(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM incidents WHERE status != 'resolved'"
        ).fetchone()

        return int(row["count"])

    # =================================================================
    # INCIDENTS
    # =================================================================

    def save_incident(self, incident) -> None:
        payload = incident.model_dump(mode="json")

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO incidents
                (
                    incident_id,
                    application_identity,
                    first_seen,
                    last_seen,
                    severity,
                    confidence,
                    status,
                    anomaly_count,
                    signal_count,
                    correlation_version,
                    incident_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    application_identity = excluded.application_identity,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    status = excluded.status,
                    anomaly_count = excluded.anomaly_count,
                    signal_count = excluded.signal_count,
                    correlation_version = excluded.correlation_version,
                    incident_json = excluded.incident_json
                """,
                (
                    incident.incident_id,
                    incident.application_identity,
                    _timestamp(incident.first_seen),
                    _timestamp(incident.last_seen),
                    incident.severity.value,
                    incident.confidence,
                    incident.status.value,
                    incident.anomaly_count,
                    incident.signal_count,
                    incident.correlation_version,
                    json.dumps(payload, sort_keys=True),
                ),
            )

            self.connection.execute(
                "DELETE FROM incident_events WHERE incident_id = ?",
                (incident.incident_id,),
            )

            self.connection.execute(
                "DELETE FROM incident_processes WHERE incident_id = ?",
                (incident.incident_id,),
            )

            for event in incident.timeline:
                self.connection.execute(
                    """
                    INSERT INTO incident_events
                    (
                        incident_id,
                        event_reference,
                        timestamp,
                        event_category,
                        process_guid,
                        severity,
                        contribution
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        event.event_reference,
                        _timestamp(event.timestamp),
                        event.event_category,
                        event.process_guid,
                        event.severity.value,
                        event.contribution,
                    ),
                )

            for node in incident.process_chain:
                self.connection.execute(
                    """
                    INSERT INTO incident_processes
                    (
                        incident_id,
                        process_guid,
                        process_id,
                        image_path,
                        parent_guid,
                        parent_pid,
                        start_time,
                        end_time,
                        hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        node.process_guid,
                        node.process_id,
                        node.image_path,
                        node.parent_guid,
                        node.parent_pid,
                        _timestamp(node.start_time),
                        _timestamp(node.end_time),
                        node.hash,
                    ),
                )

    def list_incidents(self) -> list[dict[str, object]]:
        return [
            json.loads(row["incident_json"])
            for row in self.connection.execute(
                """
                SELECT incident_json
                FROM incidents
                ORDER BY
                    CASE WHEN last_seen IS NULL THEN 1 ELSE 0 END,
                    last_seen DESC,
                    incident_id ASC
                """
            )
        ]

    def load_incident(
        self,
        incident_id: str,
    ) -> dict[str, object] | None:
        row = self.connection.execute(
            """
            SELECT incident_json
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()

        return (
            json.loads(row["incident_json"])
            if row
            else None
        )

    def _repair_incident_timestamps(self) -> None:
        """
        Idempotently repair historical NULL incidents.first_seen using only
        trustworthy timestamp evidence belonging strictly to the same incident.
        """
        with self.connection:
            cursor = self.connection.execute(
                """
                SELECT incident_id, incident_json
                FROM incidents
                WHERE first_seen IS NULL
                """
            )
            rows = cursor.fetchall()
            if not rows:
                return

            for row in rows:
                incident_id = row["incident_id"]
                raw_json = row["incident_json"]

                candidate_timestamps: list[str] = []

                # 1. Evidence from incident_events.timestamp for this incident
                event_rows = self.connection.execute(
                    """
                    SELECT timestamp
                    FROM incident_events
                    WHERE incident_id = ?
                      AND timestamp IS NOT NULL
                      AND TRIM(timestamp) != ''
                    """,
                    (incident_id,),
                ).fetchall()
                for er in event_rows:
                    candidate_timestamps.append(er["timestamp"])

                # 2. Evidence from anomalies directly associated via incident_events
                anomaly_rows = self.connection.execute(
                    """
                    SELECT a.timestamp
                    FROM anomalies a
                    JOIN incident_events ie ON a.detection_id = ie.event_reference
                    WHERE ie.incident_id = ?
                      AND a.timestamp IS NOT NULL
                      AND TRIM(a.timestamp) != ''
                    """,
                    (incident_id,),
                ).fetchall()
                for ar in anomaly_rows:
                    candidate_timestamps.append(ar["timestamp"])

                # 3. Evidence from incident_processes belonging to this incident
                proc_rows = self.connection.execute(
                    """
                    SELECT start_time
                    FROM incident_processes
                    WHERE incident_id = ?
                      AND start_time IS NOT NULL
                      AND TRIM(start_time) != ''
                    """,
                    (incident_id,),
                ).fetchall()
                for pr in proc_rows:
                    candidate_timestamps.append(pr["start_time"])

                # 4. Evidence directly persisted in incident_json (timeline or contributing_evidence)
                payload: dict[str, object] = {}
                if raw_json:
                    try:
                        loaded = json.loads(raw_json)
                        if isinstance(loaded, dict):
                            payload = loaded
                    except (json.JSONDecodeError, TypeError):
                        payload = {}

                timeline = payload.get("timeline")
                if isinstance(timeline, list):
                    for item in timeline:
                        if isinstance(item, dict) and item.get("timestamp"):
                            candidate_timestamps.append(str(item["timestamp"]))

                contributing = payload.get("contributing_evidence")
                if isinstance(contributing, list) and contributing:
                    valid_ids = [str(cid) for cid in contributing if cid]
                    if valid_ids:
                        for chunk_start in range(0, len(valid_ids), 200):
                            chunk = valid_ids[chunk_start : chunk_start + 200]
                            placeholders = ",".join("?" for _ in chunk)
                            evidence_rows = self.connection.execute(
                                f"""
                                SELECT timestamp
                                FROM anomalies
                                WHERE detection_id IN ({placeholders})
                                  AND timestamp IS NOT NULL
                                  AND TRIM(timestamp) != ''
                                """,
                                tuple(chunk),
                            ).fetchall()
                            for ev_row in evidence_rows:
                                candidate_timestamps.append(ev_row["timestamp"])

                # Parse and validate timestamps, find the earliest
                valid_datetimes: list[datetime] = []
                for ts_raw in candidate_timestamps:
                    parsed = _parse_timestamp(ts_raw)
                    if parsed is not None:
                        valid_datetimes.append(parsed)

                if not valid_datetimes:
                    # No trustworthy timestamp exists; leave first_seen NULL
                    continue

                # Find the earliest valid timestamp belonging to that incident
                earliest_dt = min(valid_datetimes)
                earliest_iso = earliest_dt.isoformat()

                # Update incident_json if present
                updated_json = raw_json
                if payload:
                    payload["first_seen"] = earliest_iso
                    updated_json = json.dumps(payload, sort_keys=True)

                self.connection.execute(
                    """
                    UPDATE incidents
                    SET first_seen = ?,
                        incident_json = ?
                    WHERE incident_id = ?
                      AND first_seen IS NULL
                    """,
                    (earliest_iso, updated_json, incident_id),
                )

    # =================================================================
    # EXPLANATIONS
    # =================================================================

    def save_explanation(self, explanation) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO incident_explanations
                (
                    incident_id,
                    explanation_json,
                    provider,
                    model_identifier,
                    schema_version,
                    prompt_version,
                    generated_at,
                    generation_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    explanation.incident_id,
                    json.dumps(
                        explanation.model_dump(mode="json"),
                        sort_keys=True,
                    ),
                    explanation.provider,
                    explanation.model_identifier,
                    explanation.schema_version,
                    explanation.prompt_version,
                    _timestamp(explanation.generated_at),
                    explanation.generation_status.value,
                ),
            )

    def load_explanation(self, incident_id: str):
        from backend.ai.models import Explanation

        row = self.connection.execute(
            """
            SELECT explanation_json
            FROM incident_explanations
            WHERE incident_id = ?
            ORDER BY generated_at DESC
            LIMIT 1
            """,
            (incident_id,),
        ).fetchone()

        return (
            Explanation.model_validate(
                json.loads(row["explanation_json"])
            )
            if row
            else None
        )

    # =================================================================
    # RETENTION
    # =================================================================

    def delete_expired(
        self,
        now: datetime | None = None,
    ) -> int:
        if self.settings.retention_days is None:
            return 0

        current = now or datetime.now(timezone.utc)
        cutoff = current - timedelta(
            days=self.settings.retention_days
        )

        deleted = 0

        with self.connection:
            rows = self.connection.execute(
                """
                SELECT id
                FROM ingestion_events
                WHERE timestamp IS NOT NULL
                  AND timestamp < ?
                """,
                (_timestamp(cutoff),),
            ).fetchall()

            for row in rows:
                ingestion_id = row["id"]

                self.connection.execute(
                    """
                    DELETE FROM process_events
                    WHERE ingestion_event_id = ?
                    """,
                    (ingestion_id,),
                )

                self.connection.execute(
                    """
                    DELETE FROM network_events
                    WHERE ingestion_event_id = ?
                    """,
                    (ingestion_id,),
                )

                self.connection.execute(
                    """
                    DELETE FROM file_events
                    WHERE ingestion_event_id = ?
                    """,
                    (ingestion_id,),
                )

                self.connection.execute(
                    """
                    DELETE FROM ingestion_events
                    WHERE id = ?
                    """,
                    (ingestion_id,),
                )

                deleted += 1

        return deleted

    # =================================================================
    # INTERNAL INSERT HELPERS
    # =================================================================

    def _insert_ingestion_event(
        self,
        event: NormalizedEvent,
        event_key: str,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO ingestion_events
            (
                event_key,
                event_kind,
                source,
                channel,
                host,
                record_id,
                event_id,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_key,
                event.kind.value,
                event.provenance.source,
                event.provenance.channel,
                event.host,
                event.record_id,
                event.event_id,
                _timestamp(event.timestamp),
            ),
        )

        return int(cursor.lastrowid)

    def _application_id(
        self,
        image_path: str | None,
        timestamp: datetime | None,
    ) -> int | None:
        if not image_path:
            return None

        value = _timestamp(timestamp) or _timestamp(
            datetime.now(timezone.utc)
        )

        self.connection.execute(
            """
            INSERT INTO applications
            (
                image_path,
                first_seen_at,
                last_seen_at
            )
            VALUES (?, ?, ?)
            ON CONFLICT(image_path) DO UPDATE SET
                last_seen_at = excluded.last_seen_at
            """,
            (
                image_path,
                value,
                value,
            ),
        )

        row = self.connection.execute(
            """
            SELECT id
            FROM applications
            WHERE image_path = ?
            """,
            (image_path,),
        ).fetchone()

        return int(row["id"]) if row else None

    def _process_reference(
        self,
        process_guid: str | None,
    ) -> int | None:
        if not process_guid:
            return None

        row = self.connection.execute(
            """
            SELECT id
            FROM process_events
            WHERE process_guid = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (process_guid,),
        ).fetchone()

        return int(row["id"]) if row else None

    def _insert_process_event(
        self,
        ingestion_id: int,
        event: ProcessCreationEvent,
    ) -> None:
        application_id = self._application_id(
            event.image,
            event.timestamp,
        )

        self.connection.execute(
            """
            INSERT INTO process_events
            (
                ingestion_event_id,
                application_id,
                timestamp,
                host,
                sysmon_event_id,
                record_id,
                process_guid,
                process_id,
                parent_process_guid,
                parent_process_id,
                parent_image,
                image_path,
                command_line,
                hashes_json,
                current_directory,
                user_name,
                integrity_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ingestion_id,
                application_id,
                _timestamp(event.timestamp),
                event.host,
                event.event_id,
                event.record_id,
                event.process_guid,
                event.process_id,
                event.parent_process_guid,
                event.parent_process_id,
                event.parent_image,
                event.image,
                event.command_line,
                json.dumps(event.hashes, sort_keys=True),
                event.current_directory,
                event.user,
                event.integrity_level,
            ),
        )

    def _insert_network_event(
        self,
        ingestion_id: int,
        event: NetworkConnectionEvent,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO network_events
            (
                ingestion_event_id,
                process_event_id,
                application_id,
                timestamp,
                host,
                sysmon_event_id,
                record_id,
                process_guid,
                process_id,
                image_path,
                command_line,
                hashes_json,
                protocol,
                initiated,
                source_ip,
                source_port,
                destination_ip,
                destination_hostname,
                destination_port
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ingestion_id,
                self._process_reference(event.process_guid),
                self._application_id(
                    event.image,
                    event.timestamp,
                ),
                _timestamp(event.timestamp),
                event.host,
                event.event_id,
                event.record_id,
                event.process_guid,
                event.process_id,
                event.image,
                event.command_line,
                json.dumps(event.hashes, sort_keys=True),
                event.protocol,
                _sqlite_bool(event.initiated),
                event.source_ip,
                event.source_port,
                event.destination_ip,
                event.destination_hostname,
                event.destination_port,
            ),
        )

    def _insert_file_event(
        self,
        ingestion_id: int,
        event: FileActivityEvent,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO file_events
            (
                ingestion_event_id,
                process_event_id,
                application_id,
                timestamp,
                host,
                sysmon_event_id,
                record_id,
                process_guid,
                process_id,
                image_path,
                command_line,
                hashes_json,
                target_filename,
                creation_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ingestion_id,
                self._process_reference(event.process_guid),
                self._application_id(
                    event.image,
                    event.timestamp,
                ),
                _timestamp(event.timestamp),
                event.host,
                event.event_id,
                event.record_id,
                event.process_guid,
                event.process_id,
                event.image,
                event.command_line,
                json.dumps(event.hashes, sort_keys=True),
                event.target_filename,
                _timestamp(event.creation_utc),
            ),
        )

    # =================================================================
    # VALIDATION
    # =================================================================

    @staticmethod
    def _validate_events(
        events: list[NormalizedEvent],
    ) -> None:
        for event in events:
            if event.event_id <= 0:
                raise DatabaseValidationError(
                    "event ID must be positive"
                )

            if (
                event.process_id is not None
                and event.process_id < 0
            ):
                raise DatabaseValidationError(
                    "process ID cannot be negative"
                )

            if isinstance(event, NetworkConnectionEvent):
                for port in (
                    event.source_port,
                    event.destination_port,
                ):
                    if (
                        port is not None
                        and not 0 <= port <= 65535
                    ):
                        raise DatabaseValidationError(
                            "network ports must be between 0 and 65535"
                        )


# =====================================================================
# MODULE HELPERS
# =====================================================================


def _event_key(event: NormalizedEvent) -> str:
    provenance = event.provenance

    identity = (
        provenance.source_record_id
        or event.record_id
    )

    if identity:
        value = "|".join(
            (
                provenance.source,
                provenance.channel,
                event.host or "",
                identity,
            )
        )
    else:
        value = "|".join(
            (
                provenance.source,
                provenance.channel,
                provenance.raw_event_hash,
            )
        )

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def _timestamp(
    value: datetime | None,
) -> str | None:
    return value.isoformat() if value else None


def _parse_timestamp(
    value: object,
) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _sqlite_bool(
    value: bool | None,
) -> int | None:
    return None if value is None else int(value)


def _loads_json(
    value: str | bytes | None,
    default: object,
) -> object:
    if value is None:
        return default

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _profile_categories(
    profile: "SignalTraceProfile",
) -> dict[str, dict[str, object]]:
    return {
        "process": profile.process_dna,
        "network": profile.network_dna,
        "file": profile.file_dna,
        "execution": profile.execution_dna,
        "temporal": profile.temporal_dna,
        "privilege": profile.privilege_dna,
    }


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()

    raise TypeError(
        f"unsupported profile value: {type(value).__name__}"
    )