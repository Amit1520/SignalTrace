import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from backend.ai.runtime.capabilities import detect_runtime_capabilities
from backend.config import SignalTraceSettings
from backend.database.repository import SQLiteRepository


class ComponentStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    detail: str


class ReadinessStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: ComponentStatus
    database: ComponentStatus
    telemetry_source: ComponentStatus
    profile_state: ComponentStatus
    local_ai: ComponentStatus
    runtime: ComponentStatus


def collect_readiness(settings: SignalTraceSettings | None = None) -> ReadinessStatus:
    settings = settings or SignalTraceSettings()
    database = _database_status(settings)
    telemetry = _telemetry_status(settings)
    runtime = detect_runtime_capabilities()
    runtime_status = "available" if runtime.status.value == "available" else runtime.status.value
    provider = settings.ai_provider.strip().lower()
    if provider in {"", "deterministic-fallback", "fallback", "none"}:
        ai_status = "available"
        ai_detail = "deterministic local fallback available"
    elif settings.ai_model_path is None:
        ai_status = "not_ready"
        ai_detail = f"provider configured ({settings.ai_provider}) but no model path is configured"
    elif not settings.ai_model_path.is_dir():
        ai_status = "not_ready"
        ai_detail = f"configured model directory is missing: {settings.ai_model_path}"
    else:
        ai_status = "available"
        ai_detail = f"local model package present and configured: {settings.ai_provider}"
    profile = _profile_status(settings)
    return ReadinessStatus(
        api=ComponentStatus(status="available", detail="API process is responding"),
        database=database,
        telemetry_source=telemetry,
        profile_state=profile,
        local_ai=ComponentStatus(status=ai_status, detail=ai_detail),
        runtime=ComponentStatus(status=runtime_status, detail=runtime.error or runtime.execution_provider or "no verified runtime provider"),
    )


def _database_status(settings: SignalTraceSettings) -> ComponentStatus:
    try:
        with SQLiteRepository(settings.database_settings()) as repository:
            repository.connection.execute("SELECT 1").fetchone()
        return ComponentStatus(status="available", detail=str(settings.database_path))
    except Exception as error:
        return ComponentStatus(status="error", detail=f"database unavailable: {type(error).__name__}")


def _profile_status(settings: SignalTraceSettings) -> ComponentStatus:
    try:
        with SQLiteRepository(settings.database_settings()) as repository:
            count = repository.connection.execute("SELECT COUNT(*) AS count FROM behavior_profiles").fetchone()["count"]
        return ComponentStatus(
            status="available" if count else "not_ready",
            detail=f"{count} stored profile(s)" if count else "no behavioral profiles stored",
        )
    except Exception as error:
        return ComponentStatus(status="error", detail=f"profile state unavailable: {type(error).__name__}")


def _telemetry_status(settings: SignalTraceSettings) -> ComponentStatus:
    if sys.platform != "win32":
        return ComponentStatus(status="unavailable", detail="Windows Sysmon source requires Windows")
    try:
        from backend.collector.source import WindowsSysmonEventSource

        return WindowsSysmonEventSource(settings.sysmon_channel).check_availability()
    except Exception as error:
        return ComponentStatus(status="unavailable", detail=f"Sysmon source unavailable: {type(error).__name__}")
