from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.ai.models import Explanation
from backend.ai.factory import create_configured_explainer
from backend.ai.service import ExplanationService
from backend.ai.runtime.capabilities import detect_runtime_capabilities
from backend.ai.runtime.models import ModelMetadata, RuntimeCapabilities
from backend.api.status import ReadinessStatus, collect_readiness
from backend.config import SignalTraceSettings
from backend.database.config import DatabaseSettings
from backend.database.repository import SQLiteRepository
from backend.incidents.models import Incident, IncidentEvent
from backend.ingestion_service import get_ingestion_status, start_continuous_ingestion, stop_continuous_ingestion
from backend.logging_config import configure_logging


configure_logging(SignalTraceSettings().log_level)

settings = SignalTraceSettings()

app = FastAPI(
    title="SignalTrace API",
    version="0.1.0",
    description="Local behavioral integrity foundation API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "Content-Type"],
)


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/readiness", response_model=ReadinessStatus, tags=["system"])
def readiness() -> ReadinessStatus:
    return collect_readiness(SignalTraceSettings())


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@app.get("/statistics", tags=["statistics"])
def get_statistics() -> dict[str, object]:
    """
    Return aggregate statistics for the dashboard.
    
    These are calculated directly from the database, not from paginated endpoints.
    """
    with SQLiteRepository(DatabaseSettings().path) as repository:
        return {
            "total_telemetry_events": repository.count_events(),
            "total_applications": repository.count_applications(),
            "total_detection_results": repository.count_detections(),
            "behavioral_deviation_count": repository.count_behavioral_deviations(),
            "total_incidents": repository.count_incidents(),
            "unresolved_incidents": repository.count_unresolved_incidents(),
        }


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

@app.get("/telemetry", tags=["telemetry"])
def list_telemetry(limit: int = 100) -> list[dict[str, object]]:
    """
    Return persisted normalized telemetry events for the dashboard.

    These events are already stored in SQLite by the ingestion pipeline.
    """
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    with SQLiteRepository(DatabaseSettings().path) as repository:
        return repository.list_recent_events(limit=limit)


# ---------------------------------------------------------------------------
# Applications / behavioral profiles
# ---------------------------------------------------------------------------

@app.get("/applications", tags=["applications"])
def list_applications() -> list[dict[str, object]]:
    """
    Return persisted application identities and their observed activity.
    """
    with SQLiteRepository(DatabaseSettings().path) as repository:
        return repository.list_applications()


@app.get("/applications/{application_identity}/profile", tags=["applications"])
def get_application_profile(application_identity: str) -> dict[str, object]:
    """
    Return the persisted SignalTrace behavioral profile for an application.
    """
    with SQLiteRepository(DatabaseSettings().path) as repository:
        payload = repository.load_profile(application_identity)

    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="application profile not found",
        )

    return payload


# ---------------------------------------------------------------------------
# Behavioral detections
# ---------------------------------------------------------------------------

@app.get("/detections", tags=["detections"])
def list_detections(limit: int = 100) -> list[dict[str, object]]:
    """
    Return persisted behavioral anomaly detections for the dashboard.
    """
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    with SQLiteRepository(DatabaseSettings().path) as repository:
        return repository.list_detections(limit=limit)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@app.get("/incidents", response_model=list[Incident], tags=["incidents"])
def list_incidents() -> list[Incident]:
    with SQLiteRepository(DatabaseSettings().path) as repository:
        return [
            Incident.model_validate(item)
            for item in repository.list_incidents()
        ]


@app.get(
    "/incidents/{incident_id}",
    response_model=Incident,
    tags=["incidents"],
)
def get_incident(incident_id: str) -> Incident:
    with SQLiteRepository(DatabaseSettings().path) as repository:
        payload = repository.load_incident(incident_id)

    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    return Incident.model_validate(payload)


@app.get(
    "/incidents/{incident_id}/timeline",
    response_model=list[IncidentEvent],
    tags=["incidents"],
)
def get_incident_timeline(incident_id: str) -> list[IncidentEvent]:
    with SQLiteRepository(DatabaseSettings().path) as repository:
        payload = repository.load_incident(incident_id)

    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    return [
        IncidentEvent.model_validate(item)
        for item in payload["timeline"]
    ]


@app.get(
    "/incidents/{incident_id}/explanation",
    response_model=Explanation,
    tags=["incidents"],
)
def get_incident_explanation(incident_id: str, refresh: bool = False) -> Explanation:
    with SQLiteRepository(DatabaseSettings().path) as repository:
        existing = repository.load_explanation(incident_id)

        # Reuse a previously successful model-generated explanation, unless
        # the caller explicitly asks for a fresh one.
        if existing is not None and not refresh:
            existing_status = getattr(
                existing.generation_status,
                "value",
                existing.generation_status,
            )

            if existing_status == "generated":
                return existing

        payload = repository.load_incident(incident_id)

        if payload is None:
            raise HTTPException(
                status_code=404,
                detail="incident not found",
            )

        result = (
            ExplanationService(
                create_configured_explainer(SignalTraceSettings())
            )
            .explain(Incident.model_validate(payload))
        )

        explanation = result.explanation

        if explanation is None:
            raise HTTPException(
                status_code=503,
                detail="explanation unavailable",
            )

        repository.save_explanation(explanation)

        return explanation

# ---------------------------------------------------------------------------
# AI / runtime
# ---------------------------------------------------------------------------

@app.get(
    "/ai/runtime",
    response_model=RuntimeCapabilities,
    tags=["ai"],
)
def get_ai_runtime() -> RuntimeCapabilities:
    return detect_runtime_capabilities()


@app.get(
    "/ai/model",
    response_model=ModelMetadata,
    tags=["ai"],
)
def get_ai_model() -> ModelMetadata:
    current = SignalTraceSettings()
    model_path = current.ai_model_path
    if current.ai_provider.lower() in {"deterministic-fallback", "fallback", "none", ""}:
        return ModelMetadata(
            name="deterministic-fallback",
            version="structured-evidence-1",
            format="structured",
            compatibility_status="fallback provider active",
        )
    if model_path is None:
        return ModelMetadata(
            name="unconfigured",
            version="unknown",
            compatibility_status="AI provider configured but model path is missing",
        )
    config_path = model_path / "genai_config.json"
    model_name = "llama-3.2-3b-instruct"
    model_version = "3B"
    model_size_bytes: int | None = None
    compatibility_status = "configured model directory is missing"

    if model_path.is_dir():
        compatibility_status = "model directory present; GenAI runtime initialization not yet verified"
        try:
            import json
            config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
            model_section = config.get("model", {}) if isinstance(config, dict) else {}
            if isinstance(model_section, dict):
                model_name = str(model_section.get("name") or model_name)
                model_version = str(model_section.get("version") or model_version)
            if config_path.is_file():
                model_size_bytes = sum(
                    path.stat().st_size
                    for path in model_path.rglob("*")
                    if path.is_file()
                )
                compatibility_status = "GenAI model package detected"
        except (OSError, ValueError, TypeError):
            compatibility_status = "model directory present but metadata could not be read"

    return ModelMetadata(
        name=model_name,
        version=model_version,
        format="onnx-genai",
        context_limit=4096,
        model_path=str(model_path),
        model_size_bytes=model_size_bytes,
        compatibility_status=compatibility_status,
    )


# ---------------------------------------------------------------------------
# Continuous Ingestion
# ---------------------------------------------------------------------------

@app.get("/ingestion/status", tags=["ingestion"])
def get_ingestion_status_endpoint() -> dict[str, object]:
    """Get the current status of the continuous ingestion service."""
    return get_ingestion_status()


@app.post("/ingestion/start", tags=["ingestion"])
def start_ingestion(interval_seconds: int = 10) -> dict[str, object]:
    """Start the continuous Sysmon ingestion service."""
    start_continuous_ingestion(max(1, interval_seconds))
    return {"status": "started", "interval_seconds": max(1, interval_seconds)}


@app.post("/ingestion/stop", tags=["ingestion"])
def stop_ingestion() -> dict[str, object]:
    """Stop the continuous Sysmon ingestion service."""
    stop_continuous_ingestion()
    return {"status": "stopped"}