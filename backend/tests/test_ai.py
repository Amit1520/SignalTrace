from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.ai.evidence import build_explanation_evidence
from backend.ai.fallback import DeterministicFallbackExplainer
from backend.ai.mock import MockLocalExplainer
from backend.ai.models import ExplanationEvidence, GenerationStatus
from backend.ai.service import ExplanationService
from backend.database.repository import SQLiteRepository
from backend.incidents.correlator import IncidentCorrelator
from backend.tests.test_incidents import detection
from backend.detection.models import SignalCategory
from backend.api.main import app


def incident_fixture():
    return IncidentCorrelator().correlate([
        detection("a", 0, SignalCategory.PROCESS),
        detection("b", 1, SignalCategory.NETWORK),
    ])[0]


def test_evidence_is_strict_and_minimizes_paths() -> None:
    evidence = build_explanation_evidence(incident_fixture())

    assert isinstance(evidence, ExplanationEvidence)
    assert evidence.process_chain[0]["image_path"].startswith(".../")
    assert "C:\\Tools" not in str(evidence.model_dump())
    assert evidence.known_limitations


def test_deterministic_fallback_is_grounded_and_investigation_only() -> None:
    evidence = build_explanation_evidence(incident_fixture())
    explanation = DeterministicFallbackExplainer().explain_incident(evidence)

    assert explanation.generation_status is GenerationStatus.FALLBACK
    assert explanation.provider == "deterministic-fallback"
    assert all("terminate" not in item.lower() for item in explanation.recommended_investigation)
    assert all("malware" not in item.lower() for item in explanation.summary.splitlines())


def test_mock_provider_valid_response_is_validated() -> None:
    evidence = build_explanation_evidence(incident_fixture())
    response = {
        "incident_id": evidence.incident_id,
        "summary": "The supplied evidence shows behavioral deviation.",
        "what_changed": [evidence.signals[0].observation],
        "why_unusual": [evidence.signals[0].deviation],
        "evidence": [evidence.signals[0].reference],
        "uncertainty": ["The supplied evidence is limited."],
        "recommended_investigation": ["Review the supplied evidence."],
    }

    result = ExplanationService(MockLocalExplainer(response)).explain(incident_fixture())

    assert result.explanation is not None
    assert result.generation_status is GenerationStatus.GENERATED


def test_malformed_provider_output_uses_fallback() -> None:
    result = ExplanationService(MockLocalExplainer(response="not-json")).explain(incident_fixture())

    assert result.explanation is not None
    assert result.generation_status is GenerationStatus.FALLBACK
    assert result.error == "model output was not valid JSON"


def test_ungrounded_provider_output_is_rejected_and_falls_back() -> None:
    result = ExplanationService(
        MockLocalExplainer(response={
            "summary": "Unsupported invented fact.",
            "what_changed": ["invented process"],
            "why_unusual": ["invented reason"],
            "evidence": ["invented reference"],
            "uncertainty": [],
            "recommended_investigation": ["Review evidence."],
        })
    ).explain(incident_fixture())

    assert result.generation_status is GenerationStatus.FALLBACK
    assert result.error == "model output contained unsupported evidence"


def test_explanation_persistence_and_reload(tmp_path) -> None:
    incident = incident_fixture()
    explanation = ExplanationService().explain(incident).explanation
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        repository.save_incident(incident)
        repository.save_explanation(explanation)
        loaded = repository.load_explanation(incident.incident_id)

    assert loaded is not None
    assert loaded.provider == "deterministic-fallback"
    assert loaded.schema_version == "1.0"


def test_explanation_api_generates_reads_and_handles_missing(tmp_path, monkeypatch) -> None:
    incident = incident_fixture()
    path = tmp_path / "signaltrace.sqlite3"
    with SQLiteRepository(path) as repository:
        repository.save_incident(incident)
    monkeypatch.setattr("backend.api.main.DatabaseSettings", lambda: type("Settings", (), {"path": path})())
    client = TestClient(app)

    first = client.get(f"/incidents/{incident.incident_id}/explanation")
    second = client.get(f"/incidents/{incident.incident_id}/explanation")
    missing = client.get("/incidents/missing/explanation")

    assert first.status_code == 200
    assert first.json()["provider"] == "deterministic-fallback"
    assert second.status_code == 200
    assert missing.status_code == 404
