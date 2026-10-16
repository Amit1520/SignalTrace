"""
Create a synthetic HIGH-severity incident for SignalTrace UI and AI testing.

- Does not invoke detection or correlation engines.
- Writes directly to the existing SQLite incidents table.
- Uses the project's root-level data/signaltrace.sqlite3 database.
- Generates a unique incident ID on each run.

Run from the SignalTrace project root or the tests directory:

    python tests/create_test_high_incident.py

Or, from the tests directory:

    python create_test_high_incident.py

Verify using PowerShell:

    Invoke-RestMethod "http://127.0.0.1:8000/incidents?limit=1"
"""

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Resolve the SignalTrace project root from this script's location.
# This script is expected to be inside the project's tests directory.
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

NEW_DB_PATH = PROJECT_ROOT / "data" / "signaltrace.sqlite3"
LEGACY_DB_PATH = PROJECT_ROOT / "data" / "securitydna.sqlite3"
DB_PATH = NEW_DB_PATH if NEW_DB_PATH.exists() else LEGACY_DB_PATH

APP_PATH = r"C:\Windows\System32\testtool.exe"
CHILD_PATH = r"C:\Windows\System32\cmd.exe"


def make_id(prefix: str) -> str:
    """Generate a unique, deterministic-format identifier."""
    return hashlib.sha256(
        f"{prefix}-{uuid.uuid4()}".encode("utf-8")
    ).hexdigest()


def main() -> None:
    if not DB_PATH.is_file():
        raise FileNotFoundError(
            f"Database not found: {DB_PATH}\n"
            "Check that the SignalTrace project contains "
            "data/signaltrace.sqlite3."
        )

    now = datetime.now(timezone.utc)
    first_seen = now - timedelta(minutes=2)

    incident_id = make_id("test-high")
    detection_id_1 = make_id("test-detection-1")
    detection_id_2 = make_id("test-detection-2")

    parent_guid = "{11111111-0000-0000-0000-000000000001}"
    child_guid = "{11111111-0000-0000-0000-000000000002}"

    process_chain = [
        {
            "process_guid": parent_guid,
            "process_id": 9001,
            "image_path": APP_PATH,
            "parent_guid": None,
            "parent_pid": None,
            "start_time": first_seen.isoformat(),
            "end_time": None,
            "hash": None,
        },
        {
            "process_guid": child_guid,
            "process_id": 9002,
            "image_path": CHILD_PATH,
            "parent_guid": parent_guid,
            "parent_pid": 9001,
            "start_time": (
                first_seen + timedelta(seconds=10)
            ).isoformat(),
            "end_time": None,
            "hash": None,
        },
    ]

    timeline = [
        {
            "event_reference": detection_id_1,
            "timestamp": first_seen.isoformat(),
            "event_category": "process",
            "process_guid": parent_guid,
            "parent_process_guid": None,
            "description": (
                "Synthetic test event: the application started "
                "a child command process."
            ),
            "severity": "high",
            "contribution": 0.9,
            "provenance": [detection_id_1],
        },
        {
            "event_reference": detection_id_1,
            "timestamp": first_seen.isoformat(),
            "event_category": "execution",
            "process_guid": parent_guid,
            "parent_process_guid": None,
            "description": (
                "Synthetic test event: an unusual command "
                "execution pattern was observed."
            ),
            "severity": "high",
            "contribution": 0.9,
            "provenance": [detection_id_1],
        },
        {
            "event_reference": detection_id_2,
            "timestamp": (
                first_seen + timedelta(minutes=1)
            ).isoformat(),
            "event_category": "temporal",
            "process_guid": parent_guid,
            "parent_process_guid": None,
            "description": (
                "Synthetic test event: activity occurred "
                "at an unusual time."
            ),
            "severity": "medium",
            "contribution": 0.6,
            "provenance": [detection_id_2],
        },
    ]

    incident = {
        "incident_id": incident_id,
        "application_identity": APP_PATH,
        "first_seen": first_seen.isoformat(),
        "last_seen": now.isoformat(),
        "duration": "PT120S",
        "severity": "high",
        "confidence": 0.85,
        "status": "open",
        "anomaly_count": 2,
        "signal_count": 3,
        "affected_processes": [parent_guid, child_guid],
        "process_chain": process_chain,
        "timeline": timeline,
        "contributing_evidence": [
            detection_id_1,
            detection_id_2,
        ],
        "correlation_version": "1.0",
    }

    # Open the existing database without creating a new database
    # if the specified path is incorrect.
    connection = sqlite3.connect(
        f"{DB_PATH.as_uri()}?mode=rw",
        uri=True,
        timeout=10,
    )

    try:
        table_exists = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'incidents'
            """
        ).fetchone()

        if table_exists is None:
            raise RuntimeError(
                f"The incidents table does not exist in {DB_PATH}"
            )

        connection.execute(
            """
            INSERT INTO incidents (
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
            """,
            (
                incident_id,
                APP_PATH,
                incident["first_seen"],
                incident["last_seen"],
                "high",
                0.85,
                "open",
                2,
                3,
                "1.0",
                json.dumps(incident),
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print("Created synthetic HIGH-severity incident.")
    print(f"Database:    {DB_PATH}")
    print(f"Incident ID: {incident_id}")
    print(f"Application: {APP_PATH}")
    print("Severity:    HIGH")
    print("Status:      OPEN")


if __name__ == "__main__":
    main()