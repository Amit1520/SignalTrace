from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from backend.baseline.builder import BaselineBuilder, BaselineSettings
from backend.database.repository import SQLiteRepository
from backend.detection.engine import BehavioralDetector, DetectionConfig
from backend.detection.models import DetectionResult, Severity, SignalCategory
from backend.detection.vector import observation_from_row
from backend.features.extractor import FeatureExtractor
from backend.incidents.correlator import CorrelationConfig, IncidentCorrelator
from backend.normalization.models import (
    EventProvenance,
    FileActivityEvent,
    NetworkConnectionEvent,
    ProcessCreationEvent,
)

APP = "c:/synthetic/signaltrace-demo.exe"
BASE_TIME = datetime(2026, 9, 14, 9, tzinfo=timezone.utc)


class ScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    baseline_state: str
    observed_behavior: str
    expected_result: str
    actual_result: str
    deterministic_signals: list[str] = Field(default_factory=list)
    statistical_result: str = "not run"
    final_score: float | None = None
    severity: str | None = None
    passed: bool
    mismatch: str | None = None


class BenchmarkRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_count: int
    ingestion_ms: float
    ingestion_events_per_second: float
    feature_extraction_ms: float
    profile_generation_ms: float
    detection_ms: float | None
    correlation_ms: float
    end_to_end_ms: float
    memory_mb: float | None = None


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime
    environment: dict[str, str]
    database_configuration: dict[str, str]
    model_configuration: dict[str, str]
    scenarios: list[ScenarioResult]
    benchmarks: list[BenchmarkRow]
    security_checks: dict[str, str]


@dataclass(frozen=True)
class SyntheticWorkload:
    events: list[ProcessCreationEvent | NetworkConnectionEvent | FileActivityEvent]


def make_process(record_id: str, timestamp: datetime = BASE_TIME, *, image: str = APP, guid: str | None = "proc-1", parent_guid: str | None = "parent-1", parent_image: str | None = "c:/windows/explorer.exe", process_id: int = 100, command_line: str | None = "signaltrace-demo.exe --worker") -> ProcessCreationEvent:
    return ProcessCreationEvent(
        timestamp=timestamp,
        host="synthetic-host",
        event_id=1,
        record_id=record_id,
        process_guid=guid,
        process_id=process_id,
        parent_process_guid=parent_guid,
        parent_process_id=50 if parent_guid else None,
        parent_image=parent_image,
        image=image,
        command_line=command_line,
        hashes={"SHA256": "synthetic-hash"},
        provenance=EventProvenance(channel="synthetic/fixture", source_record_id=record_id, raw_event_hash=f"hash-{record_id}"),
        current_directory="c:/synthetic",
        user="SYNTHETIC/user",
        integrity_level="Medium",
    )


def make_network(record_id: str, timestamp: datetime = BASE_TIME + timedelta(seconds=1), *, destination: str = "198.51.100.10", guid: str | None = "proc-1", port: int = 443) -> NetworkConnectionEvent:
    return NetworkConnectionEvent(
        timestamp=timestamp,
        host="synthetic-host",
        event_id=3,
        record_id=record_id,
        process_guid=guid,
        process_id=100,
        image=APP,
        command_line="signaltrace-demo.exe --worker",
        hashes={"SHA256": "synthetic-hash"},
        provenance=EventProvenance(channel="synthetic/fixture", source_record_id=record_id, raw_event_hash=f"hash-{record_id}"),
        protocol="tcp",
        initiated=True,
        source_ip="192.0.2.10",
        source_port=50000,
        destination_ip=destination,
        destination_hostname="synthetic.example",
        destination_port=port,
    )


def make_file(record_id: str, timestamp: datetime = BASE_TIME + timedelta(seconds=2), *, path: str = "c:/synthetic/output.txt", guid: str | None = "proc-1") -> FileActivityEvent:
    return FileActivityEvent(
        timestamp=timestamp,
        host="synthetic-host",
        event_id=11,
        record_id=record_id,
        process_guid=guid,
        process_id=100,
        image=APP,
        provenance=EventProvenance(channel="synthetic/fixture", source_record_id=record_id, raw_event_hash=f"hash-{record_id}"),
        target_filename=path,
        creation_utc=timestamp,
    )


def stable_workload(event_count: int) -> SyntheticWorkload:
    events: list[ProcessCreationEvent | NetworkConnectionEvent | FileActivityEvent] = []
    for index in range(event_count):
        timestamp = BASE_TIME + timedelta(seconds=index)
        remainder = index % 5
        if remainder < 3:
            events.append(make_process(f"stable-{index}", timestamp))
        elif remainder == 3:
            events.append(make_network(f"stable-{index}", timestamp))
        else:
            events.append(make_file(f"stable-{index}", timestamp))
    return SyntheticWorkload(events)


def _profile(repository: SQLiteRepository, minimum: int = 1):
    return BaselineBuilder(repository, BaselineSettings(minimum_observations=minimum)).build(APP)


def _scenario_result(name: str, expected: str, outcome, baseline: str, observed: str) -> ScenarioResult:
    result = outcome.result
    signals = [signal.signal_type for signal in result.contributing_signals] if result else []
    actual = "insufficient baseline" if outcome.insufficient_baseline else ("incompatible schema" if outcome.incompatible_schema else ("behavioral deviation" if result and signals else "normal behavior"))
    passed = actual == expected
    return ScenarioResult(
        scenario=name,
        baseline_state=baseline,
        observed_behavior=observed,
        expected_result=expected,
        actual_result=actual,
        deterministic_signals=signals,
        final_score=result.anomaly_score if result else None,
        severity=result.severity.value if result else None,
        passed=passed,
        mismatch=None if passed else f"expected {expected}, got {actual}",
    )


def run_detection_scenarios() -> list[ScenarioResult]:
    scenarios: list[ScenarioResult] = []
    with tempfile.TemporaryDirectory(prefix="signaltrace-phase9-") as directory:
        with SQLiteRepository(Path(directory) / "scenarios.sqlite3") as repository:
            repository.insert_events([make_process("base-process"), make_network("base-network"), make_file("base-file")])
            profile = _profile(repository)
            detector = BehavioralDetector(DetectionConfig(minimum_profile_observations=1))
            rows = repository.list_events("network_connection")
            normal = observation_from_row("network_connection", rows[0], profile)
            scenarios.append(_scenario_result("stable normal application behavior", "normal behavior", detector.detect(normal, profile), "ready profile", "known destination and port"))
            changed = make_network("changed-destination", destination="8.8.8.8", port=8443)
            repository.insert_events([changed])
            row = repository.list_events("network_connection")[-1]
            scenarios.append(_scenario_result("new network destination and port", "behavioral deviation", detector.detect(observation_from_row("network_connection", row, profile), profile), "ready profile", "new external destination and port"))
            new_file = make_file("changed-file", path="c:/synthetic/cache/new.bin")
            repository.insert_events([new_file])
            row = repository.list_events("file_activity")[-1]
            scenarios.append(_scenario_result("new file behavior", "behavioral deviation", detector.detect(observation_from_row("file_activity", row, profile), profile), "ready profile", "new directory, path, and extension"))
            new_process = make_process("changed-process", image="c:/synthetic/new-tool.exe", guid="proc-new", parent_guid="proc-1", parent_image=APP)
            repository.insert_events([new_process])
            row = repository.list_events("process_creation")[-1]
            scenarios.append(_scenario_result("new executable and child process", "behavioral deviation", detector.detect(observation_from_row("process_creation", row, profile), profile), "ready profile", "new executable and parent relationship"))
            legitimate_update = make_network("legitimate-update", destination="198.51.100.20", port=443)
            repository.insert_events([legitimate_update])
            row = repository.list_events("network_connection")[-1]
            scenarios.append(_scenario_result("legitimate software update", "behavioral deviation", detector.detect(observation_from_row("network_connection", row, profile), profile), "ready profile", "new update destination; requires human review"))
            temporal = make_process("temporal", BASE_TIME.replace(hour=23))
            repository.insert_events([temporal])
            row = repository.list_events("process_creation")[-1]
            scenarios.append(_scenario_result("temporal deviation", "behavioral deviation", detector.detect(observation_from_row("process_creation", row, profile), profile), "activity observed at hour 09", "activity observed at hour 23"))
            incomplete = make_process("incomplete", guid=None, parent_guid=None, parent_image=None, command_line=None)
            repository.insert_events([incomplete])
            row = next(item for item in repository.list_events("process_creation") if item["record_id"] == "incomplete")
            scenarios.append(_scenario_result("missing and incomplete telemetry", "normal behavior", detector.detect(observation_from_row("process_creation", row, profile), profile), "ready profile", "missing GUID, parent, and command line"))
            duplicate = repository.insert_events([make_process("base-process")])
            scenarios.append(ScenarioResult(scenario="repeated identical event ingestion", baseline_state="event already stored", observed_behavior="same source record inserted again", expected_result="duplicate rejected", actual_result=f"{duplicate.duplicates} duplicate(s)", passed=duplicate.inserted == 0 and duplicate.duplicates == 1))
        with SQLiteRepository(Path(directory) / "sparse.sqlite3") as repository:
            repository.insert_events([make_process("sparse")])
            sparse_profile = _profile(repository, minimum=5)
            observation = observation_from_row("process_creation", repository.list_events("process_creation")[0], sparse_profile)
            scenarios.append(_scenario_result("sparse observations", "insufficient baseline", detector.detect(observation, sparse_profile), "one observation; threshold five", "single process event"))
    return scenarios


def run_correlation_scenarios() -> list[ScenarioResult]:
    from backend.detection.models import BaselineComparison, Signal

    def detection(identifier: str, offset: int, category: SignalCategory, application: str = "app", guid: str | None = "proc-1", parent: str | None = None) -> DetectionResult:
        return DetectionResult(
            detection_id=identifier, application_identity=application, timestamp=BASE_TIME + timedelta(seconds=offset), anomaly_score=.5, severity=Severity.LOW, confidence=.8, statistical_contribution=0, deterministic_contribution=.5,
            contributing_signals=[Signal(category=category, signal_type=f"{category.value}_deviation", deviation="synthetic baseline mismatch", weight=.5, contribution=.5)], baseline_comparison=BaselineComparison(profile_version=1, profile_status="ready", feature_schema_version="1.0", observation_count=20, compatible=True), provenance_references=[identifier], process_guid=guid, parent_process_guid=parent, process_id=100, image_path=APP,
        )

    correlator = IncidentCorrelator()
    related = correlator.correlate([detection("p", 0, SignalCategory.PROCESS), detection("n", 1, SignalCategory.NETWORK), detection("f", 2, SignalCategory.FILE, parent="proc-1")])
    repeated = correlator.correlate([detection("p", 0, SignalCategory.PROCESS), detection("n", 1, SignalCategory.NETWORK)], related)
    separate = correlator.correlate([detection("a", 0, SignalCategory.PROCESS, application="app-a"), detection("b", 1, SignalCategory.NETWORK, application="app-b")])
    pid_reuse = correlator.correlate([detection("pid-a", 0, SignalCategory.PROCESS, guid="proc-a"), detection("pid-b", 1, SignalCategory.PROCESS, guid="proc-b")])
    return [
        ScenarioResult(scenario="same process and categories correlate", baseline_state="three related detections", observed_behavior="process, network, and file within two seconds", expected_result="one incident", actual_result=f"{len(related)} incident(s)", passed=len(related) == 1),
        ScenarioResult(scenario="duplicate correlation is idempotent", baseline_state="existing incident", observed_behavior="same detection IDs correlated twice", expected_result="unchanged incident", actual_result=f"{repeated[0].anomaly_count if repeated else 0} anomalies", passed=bool(repeated and repeated[0].anomaly_count == 3)),
        ScenarioResult(scenario="different applications remain separate", baseline_state="two applications", observed_behavior="close timestamps only", expected_result="no incident", actual_result=f"{len(separate)} incident(s)", passed=len(separate) == 0),
        ScenarioResult(scenario="PID reuse does not merge process GUIDs", baseline_state="same PID; distinct GUIDs", observed_behavior="two unrelated process identities", expected_result="no incident", actual_result=f"{len(pid_reuse)} incident(s)", passed=len(pid_reuse) == 0),
    ]


def benchmark(event_count: int) -> BenchmarkRow:
    workload = stable_workload(event_count)
    with tempfile.TemporaryDirectory(prefix="signaltrace-phase9-benchmark-") as directory:
        path = Path(directory) / "benchmark.sqlite3"
        started = time.perf_counter()
        with SQLiteRepository(path) as repository:
            insert_start = time.perf_counter()
            repository.insert_events(workload.events)
            ingestion_ms = (time.perf_counter() - insert_start) * 1000
            feature_start = time.perf_counter()
            FeatureExtractor(repository).extract()
            feature_ms = (time.perf_counter() - feature_start) * 1000
            profile_start = time.perf_counter()
            profile = _profile(repository)
            profile_ms = (time.perf_counter() - profile_start) * 1000
            detection_start = time.perf_counter()
            detector = BehavioralDetector(DetectionConfig(minimum_profile_observations=1))
            row = repository.list_events("process_creation")[0]
            detector.detect(observation_from_row("process_creation", row, profile), profile)
            detection_ms = (time.perf_counter() - detection_start) * 1000
            correlation_start = time.perf_counter()
            from backend.detection.models import BaselineComparison, Signal

            detections = [DetectionResult(detection_id=f"bench-{index}", application_identity="bench", timestamp=BASE_TIME + timedelta(seconds=index), anomaly_score=.2, severity=Severity.LOW, confidence=.5, statistical_contribution=0, deterministic_contribution=.2, contributing_signals=[Signal(category=SignalCategory.PROCESS, signal_type="bench", deviation="synthetic", weight=.1, contribution=.1)], baseline_comparison=BaselineComparison(profile_version=1, profile_status="ready", feature_schema_version="1.0", observation_count=event_count, compatible=True), provenance_references=[str(index)], process_guid="bench-process", process_id=1, image_path=APP) for index in range(event_count)]
            IncidentCorrelator().correlate(detections)
            correlation_ms = (time.perf_counter() - correlation_start) * 1000
        end_to_end_ms = (time.perf_counter() - started) * 1000
    return BenchmarkRow(event_count=event_count, ingestion_ms=ingestion_ms, ingestion_events_per_second=event_count / (ingestion_ms / 1000) if ingestion_ms else 0, feature_extraction_ms=feature_ms, profile_generation_ms=profile_ms, detection_ms=detection_ms, correlation_ms=correlation_ms, end_to_end_ms=end_to_end_ms)


def run_phase9_validation() -> ValidationReport:
    scenarios = run_detection_scenarios() + run_correlation_scenarios()
    return ValidationReport(
        generated_at=datetime.now(timezone.utc),
        environment={"os": platform.platform(), "python": sys.version.split()[0], "architecture": platform.machine(), "processor": platform.processor() or "unreported"},
        database_configuration={"engine": "sqlite3", "journal_mode": "default", "synthetic_data": "deterministic; local temporary files"},
        model_configuration={"deterministic_detector": "BehavioralDetector", "statistical_detector": "not used in scenario harness", "random_seed": "not applicable"},
        scenarios=scenarios,
        benchmarks=[benchmark(count) for count in (100, 1000, 10000)],
        security_checks={"network_calls": "none added", "shell_execution": "none", "real_malware": "not used", "telemetry_transmission": "none", "temporary_artifacts": "cleaned automatically"},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic SignalTrace Phase 9 validation")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_phase9_validation()
    rendered = report.model_dump_json(indent=2)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
