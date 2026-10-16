import json
from pathlib import Path

from backend.api.status import collect_readiness
from backend.collector.config import SysmonCollectorSettings
from backend.config import SignalTraceSettings
from backend.database.config import DatabaseSettings
from backend.smoke import run_smoke_test


def test_environment_configuration_overrides_defaults(monkeypatch) -> None:
    monkeypatch.setenv("SIGNALTRACE_DATABASE_PATH", "temporary/signaltrace.sqlite3")
    monkeypatch.setenv("SIGNALTRACE_BACKEND_PORT", "8123")
    monkeypatch.setenv("SIGNALTRACE_LOG_LEVEL", "WARNING")

    settings = SignalTraceSettings()

    assert str(settings.database_path).replace("\\", "/") == "temporary/signaltrace.sqlite3"
    assert settings.backend_port == 8123
    assert settings.log_level == "WARNING"


def test_legacy_environment_prefix_is_supported_with_new_prefix_precedence(
    monkeypatch,
) -> None:
    monkeypatch.delenv("SIGNALTRACE_BACKEND_PORT", raising=False)
    monkeypatch.setenv("SECURITYDNA_BACKEND_PORT", "8123")
    monkeypatch.setenv("SIGNALTRACE_LOG_LEVEL", "ERROR")
    monkeypatch.setenv("SECURITYDNA_LOG_LEVEL", "WARNING")
    monkeypatch.delenv("SIGNALTRACE_DATABASE_PATH", raising=False)
    monkeypatch.setenv("SECURITYDNA_DATABASE_PATH", "legacy/trace.sqlite3")
    monkeypatch.delenv("SIGNALTRACE_SYSMON_CHANNEL", raising=False)
    monkeypatch.setenv("SECURITYDNA_SYSMON_CHANNEL", "Legacy-Sysmon/Operational")

    settings = SignalTraceSettings()
    database_settings = DatabaseSettings()
    collector_settings = SysmonCollectorSettings()

    assert settings.backend_port == 8123
    assert settings.log_level == "ERROR"
    assert database_settings.path == Path("legacy/trace.sqlite3")
    assert collector_settings.channel == "Legacy-Sysmon/Operational"


def test_existing_legacy_database_and_checkpoint_are_used_in_place(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in (
        "SIGNALTRACE_DATABASE_PATH",
        "SECURITYDNA_DATABASE_PATH",
        "SIGNALTRACE_CHECKPOINT_PATH",
        "SECURITYDNA_CHECKPOINT_PATH",
    ):
        monkeypatch.delenv(name, raising=False)

    data_directory = tmp_path / "data"
    data_directory.mkdir()
    legacy_database = data_directory / "securitydna.sqlite3"
    legacy_database.write_bytes(b"existing database bytes")
    legacy_checkpoint = data_directory / "securitydna-sysmon-checkpoint.json"
    legacy_checkpoint.write_text(
        '{"last_successful_record_id":"123"}', encoding="utf-8"
    )

    settings = SignalTraceSettings()

    assert settings.database_path == Path("data/securitydna.sqlite3")
    assert settings.checkpoint_path == Path("data/securitydna-sysmon-checkpoint.json")
    assert DatabaseSettings().path == Path("data/securitydna.sqlite3")
    assert SysmonCollectorSettings().checkpoint_path == Path(
        "data/securitydna-sysmon-checkpoint.json"
    )
    assert legacy_database.read_bytes() == b"existing database bytes"
    assert legacy_checkpoint.read_text(encoding="utf-8") == (
        '{"last_successful_record_id":"123"}'
    )
    assert not (data_directory / "signaltrace.sqlite3").exists()
    assert not (data_directory / "signaltrace-sysmon-checkpoint.json").exists()


def test_readiness_reports_actual_non_windows_telemetry_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALTRACE_DATABASE_PATH", str(tmp_path / "readiness.sqlite3"))

    readiness = collect_readiness(SignalTraceSettings())

    assert readiness.api.status == "available"
    assert readiness.database.status == "available"
    assert readiness.telemetry_source.status in {"available", "unavailable"}
    assert readiness.local_ai.status == "available"


def test_end_to_end_local_smoke_path() -> None:
    result = run_smoke_test()

    assert result["status"] == "passed"
    assert result["profile_created"] is True
    assert result["detections_created"] == 3
    assert result["incidents_created"] == 1
    assert result["api_incidents_status"] == 200
    assert result["api_explanation_status"] == 200
    assert result["temporary_database_cleaned"] is True
