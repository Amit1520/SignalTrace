from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from backend.path_compat import preserve_legacy_default


class SignalTraceSettings(BaseModel):
    backend_host: str = "127.0.0.1"
    backend_port: int = Field(default=8000, ge=1, le=65535)
    database_path: Path = Field(
        default=Path("data/signaltrace.sqlite3"), validate_default=True
    )
    checkpoint_path: Path = Field(
        default=Path("data/signaltrace-sysmon-checkpoint.json"),
        validate_default=True,
    )
    sysmon_channel: str = "Microsoft-Windows-Sysmon/Operational"
    sysmon_batch_size: int = Field(default=100, ge=1, le=10_000)
    sysmon_max_xml_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    retention_days: int | None = Field(default=None, ge=1)
    minimum_profile_observations: int = Field(default=5, ge=1)
    minimum_statistical_observations: int = Field(default=10, ge=2)
    detection_low_threshold: float = Field(default=0.25, ge=0, le=1)
    detection_medium_threshold: float = Field(default=0.55, ge=0, le=1)
    detection_high_threshold: float = Field(default=0.80, ge=0, le=1)
    correlation_window_seconds: int = Field(default=600, ge=1, le=86_400)
    ai_model_path: Path | None = Path("models/llama-3.2-3b-instruct")
    ai_provider: str = "onnxruntime-genai"
    log_level: str = "INFO"
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard Python logging level")
        return normalized

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def validate_cors_allowed_origins(cls, value: object) -> list[str]:
        if isinstance(value, str):
            value = [origin.strip() for origin in value.split(",") if origin.strip()]
        if not isinstance(value, list) or not all(
            isinstance(origin, str) and origin.startswith(("http://", "https://"))
            for origin in value
        ):
            raise ValueError("cors_allowed_origins must contain HTTP(S) origins")
        return value

    @field_validator("database_path")
    @classmethod
    def preserve_existing_database(cls, value: Path) -> Path:
        return preserve_legacy_default(
            value,
            current_path=Path("data/signaltrace.sqlite3"),
            legacy_path=Path("data/securitydna.sqlite3"),
        )

    @field_validator("checkpoint_path")
    @classmethod
    def preserve_existing_checkpoint(cls, value: Path) -> Path:
        return preserve_legacy_default(
            value,
            current_path=Path("data/signaltrace-sysmon-checkpoint.json"),
            legacy_path=Path("data/securitydna-sysmon-checkpoint.json"),
        )

    @classmethod
    def from_environment(cls) -> "SignalTraceSettings":
        return cls(**cls._environment_values())

    @staticmethod
    def _environment_values() -> dict[str, object]:
        values: dict[str, object] = {}
        mappings = {
            "backend_host": "SIGNALTRACE_BACKEND_HOST",
            "backend_port": "SIGNALTRACE_BACKEND_PORT",
            "database_path": "SIGNALTRACE_DATABASE_PATH",
            "checkpoint_path": "SIGNALTRACE_CHECKPOINT_PATH",
            "sysmon_channel": "SIGNALTRACE_SYSMON_CHANNEL",
            "sysmon_batch_size": "SIGNALTRACE_SYSMON_BATCH_SIZE",
            "sysmon_max_xml_bytes": "SIGNALTRACE_SYSMON_MAX_XML_BYTES",
            "retention_days": "SIGNALTRACE_RETENTION_DAYS",
            "minimum_profile_observations": "SIGNALTRACE_MINIMUM_PROFILE_OBSERVATIONS",
            "minimum_statistical_observations": "SIGNALTRACE_MINIMUM_STATISTICAL_OBSERVATIONS",
            "detection_low_threshold": "SIGNALTRACE_DETECTION_LOW_THRESHOLD",
            "detection_medium_threshold": "SIGNALTRACE_DETECTION_MEDIUM_THRESHOLD",
            "detection_high_threshold": "SIGNALTRACE_DETECTION_HIGH_THRESHOLD",
            "correlation_window_seconds": "SIGNALTRACE_CORRELATION_WINDOW_SECONDS",
            "ai_model_path": "SIGNALTRACE_AI_MODEL_PATH",
            "ai_provider": "SIGNALTRACE_AI_PROVIDER",
            "log_level": "SIGNALTRACE_LOG_LEVEL",
            "cors_allowed_origins": "SIGNALTRACE_CORS_ALLOWED_ORIGINS",
        }
        for field_name, environment_name in mappings.items():
            value = os.getenv(environment_name)
            if value is None or value == "":
                legacy_environment_name = environment_name.replace(
                    "SIGNALTRACE_", "SECURITYDNA_", 1
                )
                value = os.getenv(legacy_environment_name)
            if value is not None and value != "":
                values[field_name] = value
        return values

    def __init__(self, **data: object) -> None:
        if not data:
            data = self._environment_values()
        super().__init__(**data)

    def database_settings(self):
        from backend.database.config import DatabaseSettings

        return DatabaseSettings(path=self.database_path, retention_days=self.retention_days)

    def collector_settings(self):
        from backend.collector.config import SysmonCollectorSettings

        return SysmonCollectorSettings(
            channel=self.sysmon_channel,
            batch_size=self.sysmon_batch_size,
            checkpoint_path=self.checkpoint_path,
            max_xml_bytes=self.sysmon_max_xml_bytes,
            retention_days=self.retention_days,
        )
