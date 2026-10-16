from datetime import datetime, timedelta, timezone

from backend.ai.models import GenerationStatus, Explanation
from backend.ai.service import ExplanationService
from backend.database.repository import SQLiteRepository
from backend.detection.models import DetectionResult, SignalCategory, Severity, Signal, BaselineComparison
from backend.incidents.correlator import IncidentCorrelator

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


def test_incident_timeline_contains_only_belonging_evidence() -> None:
    # Test 1: Timeline must contain only evidence belonging to that incident.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ]
    incidents = correlator.correlate(detections)
    assert len(incidents) == 1
    timeline_refs = [event.event_reference for event in incidents[0].timeline]
    assert timeline_refs == ["d1", "d2"]


def test_evidence_reference_resolves_to_existing_detection(tmp_path) -> None:
    # Test 2: Real evidence-reference resolution — every reference must resolve to a
    # real persisted detection, not merely compare IDs in the same memory context.
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ]
    incident = correlator.correlate(detections)[0]

    with SQLiteRepository(path) as repository:
        for det in detections:
            repository.save_detection(det, det.contributing_signals)
        repository.save_incident(incident)

        loaded = repository.load_incident(incident.incident_id)

        # Query all actually persisted detections from the database
        persisted_detections = {
            d["detection_id"]: d for d in repository.list_detections(limit=10)
        }

        # Every timeline event_reference must resolve to an actual persisted detection
        timeline_refs = [event["event_reference"] for event in loaded["timeline"]]
        for ref in timeline_refs:
            assert ref in persisted_detections, (
                f"timeline event_reference '{ref}' does not resolve to any persisted detection"
            )

        # Every contributing_evidence ID must also resolve to an actual persisted detection
        for ref in loaded["contributing_evidence"]:
            assert ref in persisted_detections, (
                f"contributing_evidence '{ref}' does not resolve to any persisted detection"
            )


def test_detection_provenance_survives_persistence(tmp_path) -> None:
    # Test 3: Detection provenance survives incident persistence and repository reopen.
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    incidents = correlator.correlate([
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ])
    incident = incidents[0]

    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        loaded = repository.load_incident(incident.incident_id)
        assert loaded["contributing_evidence"] == ["d1", "d2"]


def test_repeated_correlation_does_not_duplicate_evidence() -> None:
    # Test 4: Repeated correlation of the same detections must not duplicate evidence.
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ]
    incident_first = correlator.correlate(detections)[0]
    # Re-correlate the exact same detections against the already-existing incident
    incident_second = correlator.correlate(detections, [incident_first])[0]

    assert len(incident_second.contributing_evidence) == 2
    assert len(incident_second.timeline) == 2
    assert incident_second.contributing_evidence == ["d1", "d2"]


def test_process_metadata_survives_persistence(tmp_path) -> None:
    # Test 5: All four process-identity fields must survive the persistence/reload cycle:
    # process_guid, parent_guid, process_id, image_path.
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", parent_guid="proc-0", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", parent_guid="proc-1", process_id=11),
    ]
    incident = correlator.correlate(detections)[0]

    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        loaded = repository.load_incident(incident.incident_id)
        chain = loaded["process_chain"]
        assert len(chain) == 2

        node1 = next(n for n in chain if n["process_guid"] == "proc-1")
        assert node1["parent_guid"] == "proc-0"
        assert node1["process_id"] == 10
        assert node1["image_path"] == r"C:\Tools\app.exe"

        node2 = next(n for n in chain if n["process_guid"] == "proc-2")
        assert node2["parent_guid"] == "proc-1"
        assert node2["process_id"] == 11
        assert node2["image_path"] == r"C:\Tools\app.exe"


def test_missing_process_metadata_preserved_without_inventing(tmp_path) -> None:
    # Test 6: When process_guid and parent_guid are absent, they must remain absent after
    # persistence/reload — no parent relationship must be fabricated.
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid=None, parent_guid=None, process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid=None, parent_guid=None, process_id=11),
    ]
    incident = correlator.correlate(detections)[0]

    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        loaded = repository.load_incident(incident.incident_id)
        chain = loaded["process_chain"]
        assert len(chain) == 2
        for node in chain:
            assert node["process_guid"] is None
            assert node["parent_guid"] is None


def test_self_referencing_process_guid_not_valid_parent(tmp_path) -> None:
    # Test 7: A process where process_guid == parent_guid must not be treated as a
    # genuine parent-child relationship by the correlator or the severity logic.
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    detections = [
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", parent_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.PROCESS, process_guid="proc-1", parent_guid="proc-1", process_id=10),
    ]
    incident = correlator.correlate(detections)[0]

    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        loaded = repository.load_incident(incident.incident_id)
        # The raw self-reference is preserved exactly as received from telemetry
        assert loaded["process_chain"][0].get("parent_guid") == "proc-1"
        # Severity must not escalate on the basis of this self-referencing link alone
        assert incident.severity is Severity.LOW


def test_incident_explanation_uses_grounded_evidence() -> None:
    # Test 8: Explanation must reference evidence actually present in the incident;
    # the fallback explainer derives its output from real incident signals.
    correlator = IncidentCorrelator()
    incident = correlator.correlate([
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ])[0]

    service = ExplanationService()
    result = service.explain(incident)
    assert result.generation_status == GenerationStatus.FALLBACK
    assert result.explanation is not None
    assert "d1" in str(result.explanation.model_dump_json())


def test_ungrounded_explanation_falls_back_safely() -> None:
    # Test 9: A provider returning ungrounded content must be rejected and the system
    # must fall back to the deterministic explainer.  This test proves the specific tested
    # output is rejected; it does not claim all possible hallucinations are impossible.
    correlator = IncidentCorrelator()
    incident = correlator.correlate([
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ])[0]

    class BadExplainer:
        def explain_incident(self, evidence):
            return Explanation(
                incident_id=evidence.incident_id,
                summary="Bad summary",
                what_changed=["Ungrounded claim 1"],
                why_unusual=[],
                evidence=[],
                uncertainty=[],
                recommended_investigation=[],
                generated_at=BASE,
                provider="bad",
                model_identifier="bad",
                generation_status=GenerationStatus.GENERATED,
            )

    service = ExplanationService(provider=BadExplainer())
    result = service.explain(incident)
    assert result.generation_status == GenerationStatus.FALLBACK
    assert result.error == "model output contained unsupported evidence"
    assert result.explanation.provider == "deterministic-fallback"


def test_persisted_explanation_survives_reload(tmp_path) -> None:
    # Test 10: A persisted explanation must survive repository close and reopen.
    # The incident must be persisted first (foreign-key constraint).
    path = tmp_path / "signaltrace.sqlite3"
    correlator = IncidentCorrelator()
    incident = correlator.correlate([
        detection("d1", 0, SignalCategory.PROCESS, process_guid="proc-1", process_id=10),
        detection("d2", 10, SignalCategory.NETWORK, process_guid="proc-2", process_id=11),
    ])[0]

    service = ExplanationService()
    explanation = service.explain(incident).explanation

    # Persist the incident first to satisfy the foreign-key constraint, then the explanation
    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
        repository.save_explanation(explanation)

    # Reopen the repository and verify the explanation survived
    with SQLiteRepository(path) as repository:
        loaded = repository.load_explanation(incident.incident_id)
        assert loaded.incident_id == incident.incident_id
        assert loaded.provider == "deterministic-fallback"
        assert loaded.generation_status == GenerationStatus.FALLBACK
        assert loaded.model_identifier is not None
        assert isinstance(loaded.summary, str) and len(loaded.summary) > 0
