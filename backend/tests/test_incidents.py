from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.api.main import app
from backend.database.repository import SQLiteRepository
from backend.detection.models import BaselineComparison, DetectionResult, Severity, Signal, SignalCategory
from backend.incidents.correlator import CorrelationConfig, IncidentCorrelator


BASE = datetime(2026, 9, 14, 10, tzinfo=timezone.utc)


def detection(
    detection_id: str,
    offset: int,
    category: SignalCategory,
    application: str = "app",
    process_guid: str | None = "proc-1",
    parent_guid: str | None = None,
    severity: Severity = Severity.LOW,
    process_id: int = 10,
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
        contributing_signals=[Signal(category=category, signal_type=f"{category.value}_drift", deviation="unusual activity", weight=0.5, contribution=0.5)],
        baseline_comparison=BaselineComparison(profile_version=1, profile_status="ready", feature_schema_version="1.0", observation_count=20, compatible=True),
        provenance_references=[f"record-{detection_id}"],
        process_guid=process_guid,
        parent_process_guid=parent_guid,
        process_id=process_id,
        image_path=r"C:\Tools\app.exe",
    )


def test_single_anomaly_does_not_create_incident() -> None:
    incidents = IncidentCorrelator().correlate([detection("a", 0, SignalCategory.PROCESS)])

    assert incidents == []


def test_related_anomalies_form_one_incident_with_timeline() -> None:
    detections = [
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 5, SignalCategory.NETWORK),
        detection("c", 10, SignalCategory.FILE, parent_guid="proc-1"),
    ]

    incidents = IncidentCorrelator().correlate(detections)

    assert len(incidents) == 1
    assert incidents[0].anomaly_count == 3
    assert incidents[0].signal_count == 3
    assert incidents[0].first_seen == BASE
    assert incidents[0].last_seen == BASE + timedelta(seconds=10)
    assert [item.event_reference for item in incidents[0].timeline] == ["a", "b", "c"]
    assert incidents[0].severity is Severity.MEDIUM


def test_same_process_guid_is_sufficient_relationship() -> None:
    incidents = IncidentCorrelator().correlate([
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 1, SignalCategory.PROCESS),
    ])

    assert len(incidents) == 1
    assert incidents[0].anomaly_count == 2


def test_unrelated_applications_and_outside_window_stay_separate() -> None:
    correlator = IncidentCorrelator(CorrelationConfig(correlation_window=timedelta(seconds=5)))
    detections = [
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 10, SignalCategory.NETWORK),
        detection("c", 1, SignalCategory.FILE, application="other"),
    ]

    assert correlator.correlate(detections) == []


def test_missing_process_guid_and_orphan_are_preserved_without_inventing_tree() -> None:
    detections = [
        detection("a", 0, SignalCategory.PROCESS, process_guid=None),
        detection("b", 1, SignalCategory.NETWORK, process_guid=None),
    ]

    incidents = IncidentCorrelator().correlate(detections)

    assert len(incidents) == 1
    assert len(incidents[0].process_chain) == 1
    assert incidents[0].process_chain[0].process_guid is None
    assert incidents[0].process_chain[0].process_id == 10
    assert incidents[0].affected_processes == []


def test_repeated_correlation_is_idempotent_and_new_detection_updates() -> None:
    correlator = IncidentCorrelator()
    first = correlator.correlate([detection("a", 0, SignalCategory.PROCESS), detection("b", 1, SignalCategory.NETWORK)])
    repeated = correlator.correlate([detection("a", 0, SignalCategory.PROCESS), detection("b", 1, SignalCategory.NETWORK)], first)
    updated = correlator.correlate([detection("a", 0, SignalCategory.PROCESS), detection("b", 1, SignalCategory.NETWORK), detection("c", 2, SignalCategory.FILE)], first)

    assert len(repeated) == 1
    assert repeated[0].anomaly_count == 2
    assert len(updated) == 1
    assert updated[0].anomaly_count == 3
    assert updated[0].status.value == "updated"


def test_incident_storage_reopen_and_api_endpoints(tmp_path, monkeypatch) -> None:
    detections = [detection("a", 0, SignalCategory.PROCESS), detection("b", 1, SignalCategory.NETWORK)]
    incident = IncidentCorrelator().correlate(detections)[0]
    path = tmp_path / "signaltrace.sqlite3"
    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        assert len(repository.list_incidents()) == 1
    with SQLiteRepository(path) as repository:
        assert repository.load_incident(incident.incident_id)["incident_id"] == incident.incident_id

    monkeypatch.setattr("backend.api.main.DatabaseSettings", lambda: type("Settings", (), {"path": path})())
    client = TestClient(app)
    assert client.get("/incidents").status_code == 200
    assert client.get(f"/incidents/{incident.incident_id}").status_code == 200
    assert client.get(f"/incidents/{incident.incident_id}/timeline").status_code == 200
    assert client.get("/incidents/not-present").status_code == 404


# ---------------------------------------------------------------------------
# TASK 1 — Correlation window
# ---------------------------------------------------------------------------

def test_detections_inside_window_and_span_still_correlate() -> None:
    """Two detections well inside both correlation_window and max_incident_span
    must still be merged into a single incident."""
    correlator = IncidentCorrelator(
        CorrelationConfig(
            correlation_window=timedelta(minutes=10),
            max_incident_span=timedelta(minutes=60),
        )
    )
    detections = [
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 60, SignalCategory.NETWORK),   # 1 min apart — within window
    ]
    incidents = correlator.correlate(detections)

    assert len(incidents) == 1, "Closely-spaced detections must still form one incident"
    assert incidents[0].anomaly_count == 2


def test_long_detection_chain_is_capped_by_max_incident_span() -> None:
    """A chain of detections each 9 minutes apart (within the rolling window)
    must NOT grow the incident beyond max_incident_span.

    With correlation_window=10 min and max_incident_span=30 min:
    - d0 at t=0     → new incident [first_seen=0]
    - d1 at t=9 min → within window AND within span (9 <= 30) → merged
    - d2 at t=18 min → within window (9 min gap) AND within span (18 <= 30) → merged
    - d3 at t=27 min → within window (9 min gap) AND within span (27 <= 30) → merged
    - d4 at t=36 min → within window (9 min gap) BUT span would be 36 > 30 → REJECTED → starts new candidate
    - d5 at t=45 min → within window of d4 (9 min gap), d4's span=9 min → merged into d4's candidate
    → two qualifying incidents: [d0-d3] and [d4-d5]
    """
    span = timedelta(minutes=30)
    window = timedelta(minutes=10)
    correlator = IncidentCorrelator(
        CorrelationConfig(
            correlation_window=window,
            max_incident_span=span,
        )
    )
    # 6 detections at 0, 9, 18, 27, 36, 45 minutes (each 9 min apart)
    # Alternate PROCESS/NETWORK so both groups can qualify (need >=2 categories)
    detections = [
        detection(f"d{i}", i * 9 * 60, SignalCategory.PROCESS if i % 2 == 0 else SignalCategory.NETWORK)
        for i in range(6)
    ]
    incidents = correlator.correlate(detections)

    # There must be at least 2 incidents — the first capped at ≤30 min span,
    # the second starting from d4 (rejected by span) + d5.
    assert len(incidents) >= 2, (
        f"Long rolling chain must be split by max_incident_span; got {len(incidents)} incident(s)"
    )
    # Every incident's span must not exceed max_incident_span
    for inc in incidents:
        if inc.first_seen and inc.last_seen:
            ts_first = inc.first_seen if inc.first_seen.tzinfo else inc.first_seen.replace(tzinfo=timezone.utc)
            ts_last = inc.last_seen if inc.last_seen.tzinfo else inc.last_seen.replace(tzinfo=timezone.utc)
            span_observed = ts_last - ts_first
            assert span_observed <= span, (
                f"Incident span {span_observed} exceeds max_incident_span {span}"
            )


def test_detections_outside_max_span_start_fresh_incident() -> None:
    """A detection that falls within the rolling window but would exceed the
    absolute span ceiling must start a new incident instead of being merged."""
    correlator = IncidentCorrelator(
        CorrelationConfig(
            correlation_window=timedelta(minutes=20),
            max_incident_span=timedelta(minutes=15),
        )
    )
    detections = [
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 5 * 60, SignalCategory.NETWORK),    # 5 min: within window (20), within span (15)
        detection("c", 10 * 60, SignalCategory.FILE),      # 10 min: within window (20), within span (15)
        detection("d", 18 * 60, SignalCategory.EXECUTION), # 18 min: within window (20), but span=18>15 → new
    ]
    incidents = correlator.correlate(detections)

    # d must start a fresh incident (or be excluded if only one detection)
    # At minimum the total incident count must be >= 1 and the first incident
    # must not have absorbed d (18 min span > 15 min ceiling).
    assert len(incidents) >= 1
    for inc in incidents:
        if inc.first_seen and inc.last_seen:
            ts_first = inc.first_seen if inc.first_seen.tzinfo else inc.first_seen.replace(tzinfo=timezone.utc)
            ts_last = inc.last_seen if inc.last_seen.tzinfo else inc.last_seen.replace(tzinfo=timezone.utc)
            observed_span = ts_last - ts_first
            assert observed_span <= timedelta(minutes=15) + timedelta(seconds=1), (
                f"Incident span {observed_span} exceeds max_incident_span 15min"
            )


# ---------------------------------------------------------------------------
# TASK 2 — Evidence-based confidence
# ---------------------------------------------------------------------------

def test_confidence_does_not_reach_one_from_count_alone() -> None:
    """Merging many similar detections (same category, same process, LOW severity)
    must not push confidence to 1.0."""
    correlator = IncidentCorrelator()
    # 20 PROCESS detections — same category, same process, no diversity
    detections = [
        detection(str(i), i * 10, SignalCategory.PROCESS if i % 2 == 0 else SignalCategory.NETWORK)
        for i in range(20)
    ]
    incidents = correlator.correlate(detections)

    assert len(incidents) >= 1
    for inc in incidents:
        assert inc.confidence < 1.0, (
            f"Confidence reached 1.0 at anomaly_count={inc.anomaly_count}; "
            "count alone must not saturate confidence"
        )


def test_confidence_increases_with_diverse_evidence() -> None:
    """An incident with diverse signal categories (process + network + file + parent
    process relationship + high-severity) must have higher confidence than an
    incident with a single homogeneous category."""
    correlator = IncidentCorrelator()

    # Low-diversity: two identical PROCESS detections
    mono_detections = [
        detection("m1", 0, SignalCategory.PROCESS),
        detection("m2", 5, SignalCategory.PROCESS),
    ]
    mono_incidents = correlator.correlate(mono_detections)
    assert len(mono_incidents) == 1
    mono_confidence = mono_incidents[0].confidence

    # High-diversity: PROCESS + NETWORK + FILE + parent-chain + HIGH severity
    rich_detections = [
        detection("r1", 0, SignalCategory.PROCESS, severity=Severity.HIGH),
        detection("r2", 5, SignalCategory.NETWORK, parent_guid="proc-1", severity=Severity.HIGH),
        detection("r3", 10, SignalCategory.FILE, parent_guid="proc-1", severity=Severity.MEDIUM),
        detection("r4", 15, SignalCategory.EXECUTION, severity=Severity.LOW),
    ]
    rich_incidents = correlator.correlate(rich_detections)
    assert len(rich_incidents) == 1
    rich_confidence = rich_incidents[0].confidence

    assert rich_confidence > mono_confidence, (
        f"Diverse incident confidence ({rich_confidence:.3f}) must exceed "
        f"homogeneous incident confidence ({mono_confidence:.3f})"
    )


def test_confidence_always_within_bounds() -> None:
    """Confidence must remain in [0.0, 1.0] for any combination of detections."""
    correlator = IncidentCorrelator()

    # Single detection (new candidate path — confidence = detection.confidence)
    single = [detection("s", 0, SignalCategory.PROCESS)]
    for inc in correlator.correlate(single):
        assert 0.0 <= inc.confidence <= 1.0

    # Many diverse detections (merge path — evidence-based formula)
    many = [
        detection(str(i), i * 30, cat, severity=Severity.HIGH)
        for i, cat in enumerate([
            SignalCategory.PROCESS, SignalCategory.NETWORK, SignalCategory.FILE,
            SignalCategory.EXECUTION, SignalCategory.TEMPORAL, SignalCategory.PRIVILEGE,
            SignalCategory.PROCESS, SignalCategory.NETWORK, SignalCategory.FILE,
        ])
    ]
    for inc in correlator.correlate(many):
        assert 0.0 <= inc.confidence <= 1.0, (
            f"Confidence {inc.confidence} out of [0.0, 1.0] bounds"
        )


def test_timezone_naive_and_aware_timestamps_are_handled_safely() -> None:
    """Naive timestamps (treated as UTC) and timezone-aware UTC timestamps must
    both be accepted without error, and correlation must behave consistently."""
    from backend.detection.models import BaselineComparison, Signal

    def make_detection(det_id: str, ts: datetime, cat: SignalCategory) -> DetectionResult:
        return DetectionResult(
            detection_id=det_id,
            application_identity="tz-app",
            timestamp=ts,
            anomaly_score=0.5,
            severity=Severity.LOW,
            confidence=0.6,
            statistical_contribution=0.2,
            deterministic_contribution=0.3,
            contributing_signals=[Signal(
                category=cat,
                signal_type="tz_drift",
                deviation="tz test",
                weight=0.5,
                contribution=0.5,
            )],
            baseline_comparison=BaselineComparison(
                profile_version=1,
                profile_status="ready",
                feature_schema_version="1.0",
                observation_count=10,
                compatible=True,
            ),
            provenance_references=[f"tz-{det_id}"],
            process_guid="tz-proc",
            process_id=99,
            image_path=r"C:\tz\app.exe",
        )

    naive_ts = datetime(2026, 9, 14, 10, 0, 0)          # No tzinfo
    aware_ts = datetime(2026, 9, 14, 10, 0, 5, tzinfo=timezone.utc)  # UTC-aware

    detections = [
        make_detection("tz-a", naive_ts, SignalCategory.PROCESS),
        make_detection("tz-b", aware_ts, SignalCategory.NETWORK),
    ]

    # Must not raise; both naive and aware are accepted via _utc() normalization
    incidents = IncidentCorrelator().correlate(detections)
    assert len(incidents) == 1
    assert 0.0 <= incidents[0].confidence <= 1.0


# ---------------------------------------------------------------------------
# TASK 3 — Incident Severity (Revised)
# ---------------------------------------------------------------------------

def test_high_plus_unrelated_second_category_is_not_high() -> None:
    # 1. HIGH + unrelated second category alone does NOT automatically become HIGH.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.HIGH, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, severity=Severity.LOW, process_guid="proc-2", parent_guid=None, process_id=11),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.MEDIUM

def test_high_plus_process_relationship_is_high() -> None:
    # 2. HIGH + confirmed process relationship can become HIGH.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.HIGH, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.PROCESS, severity=Severity.LOW, parent_guid="proc-1", process_guid="proc-2", process_id=11),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.HIGH

def test_high_plus_two_non_normal_categories_is_high() -> None:
    # 3. HIGH + two distinct meaningful/non-normal categories can become HIGH.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.HIGH, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, severity=Severity.LOW, process_guid="proc-2", process_id=11),
        detection("d3", 20, SignalCategory.FILE, severity=Severity.LOW, process_guid="proc-3", process_id=12),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.HIGH

def test_medium_plus_normal_plus_normal_is_not_high() -> None:
    # 4. MEDIUM + NORMAL + NORMAL does NOT become HIGH.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.MEDIUM, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, severity=Severity.NORMAL, process_guid="proc-2", process_id=11),
        detection("d3", 20, SignalCategory.FILE, severity=Severity.NORMAL, process_guid="proc-3", process_id=12),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is not Severity.HIGH
    assert incidents[0].severity is Severity.LOW

def test_medium_plus_diverse_non_normal_is_high() -> None:
    # 5. MEDIUM + genuinely diverse non-normal evidence can become HIGH.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.MEDIUM, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, severity=Severity.LOW, process_guid="proc-2", process_id=11),
        detection("d3", 20, SignalCategory.FILE, severity=Severity.LOW, process_guid="proc-3", process_id=12),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.HIGH

def test_repetitive_low_remains_low() -> None:
    # 6. Repetitive LOW remains LOW.
    correlator = IncidentCorrelator()
    detections = [
        detection(f"d{i}", i * 10, SignalCategory.PROCESS, severity=Severity.LOW, process_guid="proc-1")
        for i in range(10)
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.LOW

def test_diverse_low_remains_medium() -> None:
    # 7. Diverse LOW remains MEDIUM.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.LOW, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, severity=Severity.LOW, process_guid="proc-2", process_id=11),
        detection("d3", 20, SignalCategory.FILE, severity=Severity.LOW, process_guid="proc-3", process_id=12),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.MEDIUM

def test_isolated_high_remains_medium() -> None:
    # 8. Isolated HIGH remains MEDIUM.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.HIGH, process_guid="proc-1"),
        detection("d2", 10, SignalCategory.PROCESS, severity=Severity.NORMAL, process_guid="proc-1"),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.MEDIUM

def test_self_referencing_process_guid_is_not_corroboration() -> None:
    # 9. Self-referencing process GUID does not count as corroboration.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, severity=Severity.HIGH, process_guid="proc-1", parent_guid="proc-1"),
        detection("d2", 10, SignalCategory.PROCESS, severity=Severity.NORMAL, process_guid="proc-1", parent_guid="proc-1"),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    assert incidents[0].severity is Severity.MEDIUM
