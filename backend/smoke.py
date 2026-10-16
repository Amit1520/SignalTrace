from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from backend.ai.service import ExplanationService
from backend.baseline.builder import BaselineBuilder, BaselineSettings
from backend.database.repository import SQLiteRepository
from backend.detection.engine import BehavioralDetector, DetectionConfig
from backend.detection.vector import observation_from_row
from backend.incidents.correlator import IncidentCorrelator
from backend.validation.phase9 import APP, make_file, make_network, make_process


def run_smoke_test() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="signaltrace-smoke-") as directory:
        database_path = Path(directory) / "smoke.sqlite3"
        with SQLiteRepository(database_path) as repository:
            repository.insert_events([make_process("smoke-base-process"), make_network("smoke-base-network"), make_file("smoke-base-file")])
            profile = BaselineBuilder(repository, BaselineSettings(minimum_observations=1)).build(APP)
            if profile is None:
                raise RuntimeError("smoke test could not create a baseline profile")
            new_events = [
                make_process("smoke-new-process", image="c:/synthetic/new-tool.exe", guid="smoke-new", parent_guid="proc-1", parent_image=APP),
                make_network("smoke-new-network", destination="8.8.8.8", port=8443),
                make_file("smoke-new-file", path="c:/synthetic/new/new.bin"),
            ]
            repository.insert_events(new_events)
            detector = BehavioralDetector(DetectionConfig(minimum_profile_observations=1))
            detections = []
            for kind, record_id in (("process_creation", "smoke-new-process"), ("network_connection", "smoke-new-network"), ("file_activity", "smoke-new-file")):
                row = next(item for item in repository.list_events(kind) if item["record_id"] == record_id)
                outcome = detector.detect(observation_from_row(kind, row, profile), profile)
                if outcome.result is None:
                    raise RuntimeError(f"smoke detection failed for {kind}: {outcome.reason}")
                repository.save_detection(outcome.result, outcome.result.contributing_signals)
                detections.append(outcome.result)
            incidents = IncidentCorrelator().correlate(detections)
            if len(incidents) != 1:
                raise RuntimeError(f"smoke correlation expected one incident, got {len(incidents)}")
            repository.save_incident(incidents[0])
            explanation = ExplanationService().explain(incidents[0]).explanation
            if explanation is None:
                raise RuntimeError("smoke explanation was unavailable")
            repository.save_explanation(explanation)
            previous_database_path = os.environ.get("SIGNALTRACE_DATABASE_PATH")
            os.environ["SIGNALTRACE_DATABASE_PATH"] = str(database_path)
            try:
                from backend.api.main import app

                client = TestClient(app)
                api_incidents = client.get("/incidents")
                api_explanation = client.get(f"/incidents/{incidents[0].incident_id}/explanation")
                if api_incidents.status_code != 200 or api_explanation.status_code != 200:
                    raise RuntimeError("smoke API verification failed")
            finally:
                if previous_database_path is None:
                    os.environ.pop("SIGNALTRACE_DATABASE_PATH", None)
                else:
                    os.environ["SIGNALTRACE_DATABASE_PATH"] = previous_database_path
            return {
                "status": "passed",
                "events_inserted": 6,
                "profile_created": True,
                "detections_created": len(detections),
                "incidents_created": len(incidents),
                "explanation_provider": explanation.provider,
                "api_incidents_status": api_incidents.status_code,
                "api_explanation_status": api_explanation.status_code,
                "temporary_database_cleaned": True,
            }


if __name__ == "__main__":
    import json

    print(json.dumps(run_smoke_test(), indent=2))
