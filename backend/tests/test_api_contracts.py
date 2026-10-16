"""
Job 7 — API & End-to-End Contract Regression Tests

These tests verify the HTTP API contracts for all endpoints listed in Job 7.
They use an isolated in-memory/tmp_path SQLite database patched via monkeypatch
so they never touch the production database.

Coverage:
  /health                             → existing test_health.py
  /health/readiness                   → test_readiness_shape
  /statistics                         → test_statistics_*
  /telemetry                          → test_telemetry_*
  /applications                       → test_applications_*
  /applications/{id}/profile          → test_application_profile_*
  /detections                         → test_detections_*
  /incidents                          → test_incidents_*
  /incidents/{id}                     → test_incident_by_id_*
  /incidents/{id}/timeline            → test_incident_timeline_*
  /incidents/{id}/explanation         → covered by test_ai.py
  /ai/runtime                         → test_ai_runtime_*
  /ai/model                           → test_ai_model_*
  /ingestion/status                   → test_ingestion_status_*
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.database.repository import SQLiteRepository
from backend.detection.models import (
    BaselineComparison,
    DetectionResult,
    Severity,
    Signal,
    SignalCategory,
)
from backend.incidents.correlator import IncidentCorrelator
from backend.incidents.models import IncidentStatus

BASE = datetime(2026, 9, 14, 10, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _detection(
    detection_id: str,
    offset: int,
    category: SignalCategory,
    process_guid: str | None = "pg-1",
    parent_guid: str | None = None,
    process_id: int = 10,
    severity: Severity = Severity.LOW,
    application: str = "app",
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        application_identity=application,
        timestamp=BASE + timedelta(seconds=offset),
        anomaly_score=0.4,
        severity=severity,
        confidence=0.7,
        statistical_contribution=0.1,
        deterministic_contribution=0.3,
        contributing_signals=[
            Signal(
                category=category,
                signal_type=f"{category.value}_drift",
                deviation="unusual activity",
                weight=0.5,
                contribution=0.5,
            )
        ],
        baseline_comparison=BaselineComparison(
            profile_version=1,
            profile_status="ready",
            feature_schema_version="1.0",
            observation_count=20,
            compatible=True,
        ),
        provenance_references=[f"record-{detection_id}"],
        process_guid=process_guid,
        parent_process_guid=parent_guid,
        process_id=process_id,
        image_path=r"C:\Tools\app.exe",
    )


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "signaltrace.sqlite3"


@pytest.fixture()
def populated_db(db_path):
    """
    A SQLite database pre-populated with one incident (two correlated detections).
    Returns (path, incident) for use in tests.
    """
    detections = [
        _detection("d1", 0, SignalCategory.PROCESS, process_guid="pg-1", process_id=10),
        _detection("d2", 10, SignalCategory.NETWORK, process_guid="pg-2", process_id=11),
    ]
    incident = IncidentCorrelator().correlate(detections)[0]
    with SQLiteRepository(db_path) as repo:
        for det in detections:
            repo.save_detection(det, det.contributing_signals)
        repo.save_incident(incident)
    return db_path, incident


@pytest.fixture()
def api_client(populated_db, monkeypatch):
    """TestClient wired to the populated test database."""
    db_path, incident = populated_db
    monkeypatch.setattr(
        "backend.api.main.DatabaseSettings",
        lambda: type("S", (), {"path": db_path})(),
    )
    return TestClient(app), incident


# ---------------------------------------------------------------------------
# /health/readiness
# ---------------------------------------------------------------------------

def test_readiness_returns_all_components(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALTRACE_DATABASE_PATH", str(tmp_path / "r.sqlite3"))
    response = TestClient(app).get("/health/readiness")

    assert response.status_code == 200
    body = response.json()
    # All six required component fields must be present
    for key in ("api", "database", "telemetry_source", "profile_state", "local_ai", "runtime"):
        assert key in body, f"readiness missing component: {key}"
    # Each component must carry status and detail strings
    for key in ("api", "database", "local_ai"):
        assert isinstance(body[key]["status"], str)
        assert isinstance(body[key]["detail"], str)
    # API is always available when the process responds
    assert body["api"]["status"] == "available"


# ---------------------------------------------------------------------------
# /statistics
# ---------------------------------------------------------------------------

def test_statistics_returns_all_required_keys(api_client) -> None:
    client, _ = api_client
    response = client.get("/statistics")

    assert response.status_code == 200
    body = response.json()
    for key in (
        "total_telemetry_events",
        "total_applications",
        "total_detection_results",
        "behavioral_deviation_count",
        "total_incidents",
        "unresolved_incidents",
    ):
        assert key in body, f"statistics missing key: {key}"


def test_statistics_are_database_backed_not_frontend_derived(api_client) -> None:
    # The populated DB has 2 detections and 1 incident; values must reflect reality.
    client, _ = api_client
    body = client.get("/statistics").json()

    assert body["total_detection_results"] >= 2
    assert body["total_incidents"] >= 1
    assert body["unresolved_incidents"] >= 1


# ---------------------------------------------------------------------------
# /telemetry
# ---------------------------------------------------------------------------

def test_telemetry_returns_list(api_client) -> None:
    client, _ = api_client
    response = client.get("/telemetry")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_telemetry_limit_validation(api_client) -> None:
    client, _ = api_client
    assert client.get("/telemetry?limit=0").status_code == 400
    assert client.get("/telemetry?limit=1001").status_code == 400
    assert client.get("/telemetry?limit=1").status_code == 200


# ---------------------------------------------------------------------------
# /applications
# ---------------------------------------------------------------------------

def test_applications_returns_list(api_client) -> None:
    client, _ = api_client
    response = client.get("/applications")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_application_profile_returns_404_for_unknown(api_client) -> None:
    client, _ = api_client
    response = client.get("/applications/does-not-exist/profile")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# /detections
# ---------------------------------------------------------------------------

def test_detections_returns_list(api_client) -> None:
    client, _ = api_client
    response = client.get("/detections")

    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) >= 2


def test_detections_include_process_and_provenance_fields(api_client) -> None:
    # Fields persisted by the existing pipeline must be exposed by the API.
    client, _ = api_client
    items = client.get("/detections").json()

    for item in items:
        # Core identity
        assert "detection_id" in item
        assert "application_identity" in item
        assert "timestamp" in item
        assert "severity" in item
        assert "anomaly_score" in item
        assert "confidence" in item
        # Process identity fields
        assert "process_guid" in item
        assert "process_id" in item
        assert "image_path" in item
        # Provenance
        assert "provenance_references" in item
        # Baseline comparison
        assert "baseline_comparison" in item
        bc = item["baseline_comparison"]
        assert "profile_version" in bc
        assert "observation_count" in bc
        # Signals
        assert "contributing_signals" in item


def test_detections_limit_validation(api_client) -> None:
    client, _ = api_client
    assert client.get("/detections?limit=0").status_code == 400
    assert client.get("/detections?limit=1001").status_code == 400
    assert client.get("/detections?limit=1").status_code == 200


# ---------------------------------------------------------------------------
# /incidents
# ---------------------------------------------------------------------------

def test_incidents_returns_list(api_client) -> None:
    client, _ = api_client
    response = client.get("/incidents")

    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) >= 1


def test_incidents_response_fields(api_client) -> None:
    client, _ = api_client
    items = client.get("/incidents").json()

    for item in items:
        assert "incident_id" in item
        assert "application_identity" in item
        assert "severity" in item
        assert "confidence" in item
        assert "status" in item
        assert "anomaly_count" in item
        assert "contributing_evidence" in item
        assert "timeline" in item
        assert "process_chain" in item


def test_incidents_status_is_valid_enum_value(api_client) -> None:
    client, _ = api_client
    items = client.get("/incidents").json()
    valid = {s.value for s in IncidentStatus}

    for item in items:
        assert item["status"] in valid, f"unexpected status: {item['status']}"


# ---------------------------------------------------------------------------
# /incidents/{incident_id}
# ---------------------------------------------------------------------------

def test_incident_by_id_returns_correct_incident(api_client) -> None:
    client, incident = api_client
    response = client.get(f"/incidents/{incident.incident_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident.incident_id
    assert body["application_identity"] == incident.application_identity


def test_incident_by_id_returns_404_for_nonexistent(api_client) -> None:
    client, _ = api_client
    response = client.get("/incidents/does-not-exist-000")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_incident_by_id_does_not_fabricate_missing_data(api_client) -> None:
    # Loaded incident must reference only the contributing detections that were persisted.
    client, incident = api_client
    body = client.get(f"/incidents/{incident.incident_id}").json()

    assert set(body["contributing_evidence"]) == set(incident.contributing_evidence)
    assert body["anomaly_count"] == incident.anomaly_count


# ---------------------------------------------------------------------------
# /incidents/{incident_id}/timeline
# ---------------------------------------------------------------------------

def test_incident_timeline_returns_list(api_client) -> None:
    client, incident = api_client
    response = client.get(f"/incidents/{incident.incident_id}/timeline")

    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) >= 1


def test_incident_timeline_contains_only_belonging_evidence(api_client) -> None:
    client, incident = api_client
    items = client.get(f"/incidents/{incident.incident_id}/timeline").json()

    timeline_refs = {event["event_reference"] for event in items}
    evidence_refs = set(incident.contributing_evidence)
    # Every timeline event_reference must be one of the incident's contributing detections
    assert timeline_refs.issubset(evidence_refs), (
        f"timeline contains unexpected references: {timeline_refs - evidence_refs}"
    )


def test_incident_timeline_event_fields(api_client) -> None:
    client, incident = api_client
    items = client.get(f"/incidents/{incident.incident_id}/timeline").json()

    for event in items:
        assert "event_reference" in event
        assert "event_category" in event
        assert "severity" in event
        assert "contribution" in event
        assert "description" in event


def test_incident_timeline_returns_404_for_nonexistent(api_client) -> None:
    client, _ = api_client
    response = client.get("/incidents/does-not-exist-000/timeline")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# End-to-end chain: Detection → Incident → Timeline → API consistency
# ---------------------------------------------------------------------------

def test_api_incident_references_same_persisted_detections(api_client) -> None:
    """
    The detection IDs that went into the correlator are the same ones
    returned by /incidents/{id} contributing_evidence and /detections.
    This verifies the chain: Detection → Incident → API response remains
    consistent rather than reconstructing synthetic evidence.
    """
    client, incident = api_client

    # Fetch from API
    api_incident = client.get(f"/incidents/{incident.incident_id}").json()
    api_detections = client.get("/detections").json()

    persisted_ids = {d["detection_id"] for d in api_detections}
    evidence_ids = set(api_incident["contributing_evidence"])

    # Every contributing_evidence in the API incident must be a real persisted detection
    assert evidence_ids.issubset(persisted_ids), (
        f"Incident references detections not in /detections: {evidence_ids - persisted_ids}"
    )


# ---------------------------------------------------------------------------
# /ai/runtime
# ---------------------------------------------------------------------------

def test_ai_runtime_returns_required_fields(api_client) -> None:
    client, _ = api_client
    response = client.get("/ai/runtime")

    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "platform" in body
    assert "architecture" in body
    assert "npu_verified" in body
    # npu_verified must be an explicit boolean — never invented
    assert isinstance(body["npu_verified"], bool)


def test_ai_runtime_does_not_claim_npu_without_verification(api_client) -> None:
    # Without a real NPU environment, npu_verified must be False
    client, _ = api_client
    body = client.get("/ai/runtime").json()

    assert body["npu_verified"] is False


# ---------------------------------------------------------------------------
# /ai/model
# ---------------------------------------------------------------------------

def test_ai_model_returns_required_fields(api_client) -> None:
    client, _ = api_client
    response = client.get("/ai/model")

    assert response.status_code == 200
    body = response.json()
    assert "name" in body
    assert "version" in body
    assert "compatibility_status" in body

def test_ai_model_reports_configured_local_model(api_client) -> None:
    client, _ = api_client
    body = client.get("/ai/model").json()

    assert body["name"] == "llama-3.2-3b-instruct"
    assert body["version"] == "3B"
    assert body["format"] == "onnx-genai"
    assert body["context_limit"] == 4096
    assert body["compatibility_status"] == "GenAI model package detected"
    assert body["model_path"] == "models\\llama-3.2-3b-instruct"
    assert body["model_size_bytes"] > 0



# ---------------------------------------------------------------------------
# /ingestion/status
# ---------------------------------------------------------------------------

def test_ingestion_status_returns_required_fields(api_client) -> None:
    client, _ = api_client
    response = client.get("/ingestion/status")

    assert response.status_code == 200
    body = response.json()
    for key in (
        "active",
        "current_interval_seconds",
        "total_events_inserted",
        "total_events_read",
        "total_errors",
    ):
        assert key in body, f"ingestion/status missing key: {key}"


def test_ingestion_status_active_is_boolean(api_client) -> None:
    client, _ = api_client
    body = client.get("/ingestion/status").json()

    assert isinstance(body["active"], bool)


def test_ingestion_status_interval_is_positive_integer(api_client) -> None:
    client, _ = api_client
    body = client.get("/ingestion/status").json()

    assert isinstance(body["current_interval_seconds"], int)
    assert body["current_interval_seconds"] >= 1
