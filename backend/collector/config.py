from pathlib import Path
import os

from pydantic import BaseModel, Field, field_validator

from backend.path_compat import preserve_legacy_default


class SysmonCollectorSettings(BaseModel):
    event_source: str = "windows_sysmon"
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    batch_size: int = Field(default=100, ge=1, le=10_000)
    checkpoint_path: Path = Field(
        default=Path("data/signaltrace-sysmon-checkpoint.json"),
        validate_default=True,
    )
    max_xml_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    retention_days: int | None = Field(default=None, ge=1)

    def __init__(self, **data: object) -> None:
        if not data:
            environment = {
                "channel": "SIGNALTRACE_SYSMON_CHANNEL",
                "batch_size": "SIGNALTRACE_SYSMON_BATCH_SIZE",
                "checkpoint_path": "SIGNALTRACE_CHECKPOINT_PATH",
                "max_xml_bytes": "SIGNALTRACE_SYSMON_MAX_XML_BYTES",
                "retention_days": "SIGNALTRACE_RETENTION_DAYS",
            }
            for field, name in environment.items():
                value = os.getenv(name) or os.getenv(
                    name.replace("SIGNALTRACE_", "SECURITYDNA_", 1)
                )
                if value:
                    data[field] = value
        super().__init__(**data)

    @field_validator("checkpoint_path")
    @classmethod
    def preserve_existing_checkpoint(cls, value: Path) -> Path:
        return preserve_legacy_default(
            value,
            current_path=Path("data/signaltrace-sysmon-checkpoint.json"),
            legacy_path=Path("data/securitydna-sysmon-checkpoint.json"),
        )

    @field_validator("event_source")
    @classmethod
    def validate_event_source(cls, value: str) -> str:
        if value != "windows_sysmon":
            raise ValueError("only the windows_sysmon event source is supported")
        return value
