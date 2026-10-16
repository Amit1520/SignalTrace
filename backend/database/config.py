from pathlib import Path
import os

from pydantic import BaseModel, Field, field_validator

from backend.path_compat import preserve_legacy_default


class DatabaseSettings(BaseModel):
    path: Path = Field(
        default=Path("data/signaltrace.sqlite3"), validate_default=True
    )
    retention_days: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def preserve_existing_database(cls, value: Path) -> Path:
        return preserve_legacy_default(
            value,
            current_path=Path("data/signaltrace.sqlite3"),
            legacy_path=Path("data/securitydna.sqlite3"),
        )

    def __init__(self, **data: object) -> None:
        if not data:
            if database_path := (
                os.getenv("SIGNALTRACE_DATABASE_PATH")
                or os.getenv("SECURITYDNA_DATABASE_PATH")
            ):
                data["path"] = database_path
            if retention_days := (
                os.getenv("SIGNALTRACE_RETENTION_DAYS")
                or os.getenv("SECURITYDNA_RETENTION_DAYS")
            ):
                data["retention_days"] = retention_days
        super().__init__(**data)

    def resolved_path(self) -> Path:
        return self.path.expanduser().resolve()
