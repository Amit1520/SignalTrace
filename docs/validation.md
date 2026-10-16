# Phase 9 Validation

## Validation methodology

Phase 9 uses deterministic, local synthetic normalized events only. Fixtures cover stable process/network/file behavior, repeated launches, parent/child relationships, sparse profiles, legitimate update-like changes, new executables, new destinations, new file paths, temporal changes, incomplete telemetry, duplicate ingestion, multiple applications, PID reuse, and incident idempotency.

The harness is implemented in `backend/validation/phase9.py` and writes a machine-readable JSON report when passed `--output`. Each benchmark uses a temporary SQLite database that is removed automatically. No shell, network, cloud API, real malware, or attack tooling is used.

Profile readiness uses the existing Phase 3 threshold supplied to `BaselineBuilder`; the sparse scenario uses one observation against a threshold of five. Detection scenarios use the existing deterministic `BehavioralDetector` and do not run Isolation Forest. This keeps the result attributable to the deterministic pipeline. Statistical detector behavior remains covered by the Phase 4 tests.

## Detection results

All 9 detection/quality scenarios passed:

| Scenario | Expected | Actual | Evidence |
| --- | --- | --- | --- |
| Stable normal application | Normal behavior | Normal behavior | None |
| New network destination and port | Behavioral deviation | Behavioral deviation | `new_destination`, `unusual_port`, `new_external_connection` |
| New file behavior | Behavioral deviation | Behavioral deviation | `new_directory`, `new_file_path`, `new_extension` |
| New executable and child process | Behavioral deviation | Behavioral deviation | `new_executable_path`, `new_child_process`, `new_parent_child_relationship` |
| Legitimate software update | Behavioral deviation requiring review | Behavioral deviation | `new_destination`; low score `0.1625`, normal severity |
| Temporal deviation | Behavioral deviation | Behavioral deviation | `outside_normal_hour` plus current child-process signal |
| Missing/incomplete telemetry | Normal behavior | Normal behavior | No signal forced from missing fields |
| Repeated identical ingestion | Duplicate rejected | 1 duplicate rejected | Deterministic provenance key |
| Sparse observations | Insufficient baseline | Insufficient baseline | One observation vs threshold five |

Scores are behavioral deviation scores, not probabilities or malware classifications. The legitimate update scenario demonstrates that a baseline mismatch can be weak and normal severity rather than automatically escalated.

## False-positive observations

- A legitimate new update destination produces a deviation signal because it is not present in the historical profile. The measured score was `0.1625` with normal severity. This is an expected baseline-mismatch case requiring investigation, not a malicious classification.
- The temporal scenario also emitted `new_child_process`. This is a current implementation finding: the observation vector treats any process with a parent as a child, while the profile's child-frequency feature only records a narrower parent-image relationship. The temporal signal itself was correct, but the extra process signal may increase false positives and should be reviewed in a later detector-quality fix.
- Sparse data returns `insufficient baseline` and does not force a score.
- Missing GUID, parent, and command-line fields do not create fabricated evidence.
- Repeated identical source records are rejected by deterministic provenance deduplication.

## Correlation results

All 4 correlation scenarios passed:

- Related process/network/file detections became one incident.
- Repeated correlation preserved the existing incident and anomaly count.
- Different applications close in time remained separate.
- Distinct process GUIDs sharing a PID were not merged as PID reuse.

The PID-reuse result required a Phase 9 root-cause fix in the correlation guard: known distinct process GUIDs with the same PID and no parent relationship are now kept separate.

## Performance results

Measured on the local environment below using temporary SQLite databases and deterministic synthetic event mixes. These are environment-specific measurements, not production capacity claims.

| Events | Insert ms | Insert events/s | Features ms | Profile ms | Detection ms | Correlation ms | End-to-end ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 15.253 | 6,556 | 3.712 | 14.813 | 1.277 | 4.431 | 467.622 |
| 1,000 | 51.835 | 19,292 | 30.314 | 37.410 | 2.651 | 211.646 | 720.033 |
| 10,000 | 558.200 | 17,915 | 313.881 | 380.043 | 52.250 | 60,475.948 | 62,221.774 |

Memory was not measured because no reliable cross-platform measurement was implemented. The 10,000-event correlation result is approximately 60.5 seconds in this implementation and workload; it is an important scaling observation, not a fabricated benchmark claim.

The machine-readable report was generated in a temporary file and removed after inspection. Re-run the command in the exact commands section to produce a new report.

## Exact commands

From the repository root:

```powershell
C:/Python312/python.exe -m pytest
C:/Python312/python.exe -m pytest backend/tests/test_validation_phase9.py backend/tests/test_incidents.py
$output = Join-Path $env:TEMP "signaltrace-phase9-results.json"
C:/Python312/python.exe -m backend.validation.phase9 --output $output
```

Phase 8 compatibility checks:

```powershell
cd frontend
npm run typecheck
npm run build
```

## Environment

- OS: Windows 11 `10.0.26200`
- Python: `3.12.5`
- Architecture: `AMD64`
- Processor: `AMD64 Family 23 Model 96 Stepping 1, AuthenticAMD`
- Database: Python standard-library `sqlite3`, default journal configuration, temporary local database
- Statistical model: not used by the scenario harness; deterministic `BehavioralDetector` used for attribution
- ONNX/Snapdragon: not used or measured in Phase 9

## Security and privacy validation

- No external network calls were added.
- No telemetry was transmitted.
- No shell commands or observed commands were executed.
- No privilege escalation was used.
- No real malware or attack tooling was used.
- Fixtures are deterministic and local.
- Benchmark databases use temporary directories and automatic cleanup.
- Sensitive command lines and paths are synthetic fixture values only.

## Competition relevance

- **Technical Implementation:** Provides repeatable evidence that normalization, persistence, profiling, detection, and correlation can be evaluated as separate stages.
- **Application Use Case & Innovation:** Measures the behavioral-integrity concept directly, including legitimate baseline changes and false-positive boundaries.
- **Deployment & Accessibility:** Records environment-specific performance and keeps validation runnable offline with standard local fixtures.
- **Presentation & Documentation:** Supplies honest scenario tables, measured timings, limitations, and a machine-readable report instead of unsupported security claims.

## Limitations

- Synthetic workloads do not represent the full diversity of Windows applications or Sysmon event distributions.
- No real malware was used or needed for this validation.
- Statistical detector results were not included in the scenario harness; existing Phase 4 tests cover its deterministic training/persistence behavior.
- No Snapdragon, GPU, or NPU benchmark was performed.
- Concept drift, seasonal behavior, software updates, and changing network destinations can create legitimate deviations.
- Correlation and profile performance are workload- and environment-specific.
- These results are engineering validation, not production-grade security validation.
