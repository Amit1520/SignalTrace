# Architecture

## Current implementation

Phase 10 extends the Phase 9 implementation with deployment configuration and readiness without changing detection architecture:

```text
Windows Sysmon Event Log -> source abstraction -> safe XML parser
    -> typed normalized event -> SQLite repository -> features -> versioned profile
    -> deterministic signals + statistical detector -> evidence
    -> correlated incident -> process chain and timeline
    -> structured evidence -> local explanation
    -> optional ONNX Runtime adapter -> selected execution provider -> validated output
    -> local API -> React dashboard
HTTP client -> FastAPI application -> health contract
```

The Phase 8 frontend is a React/TypeScript/Vite shell over the existing read-only API. It polls `/incidents` and `/ai/runtime` every 15 seconds, loads incident details and explanations on demand, and never reimplements detection, profiling, or correlation logic. Application profiles and normalized live events are shown as honest unavailable/empty states because those read APIs are not yet exposed.

## Deployment boundary

`SignalTraceSettings` provides safe local defaults and environment overrides for host/port, SQLite, checkpoints, Sysmon, thresholds, retention, AI/runtime, and logging. `/health/readiness` reports API, database, telemetry source, profile, local AI, and runtime states separately; `/health` remains the compatibility liveness response. Database schema initialization is idempotent, checkpoint corruption is quarantined, and the smoke path exercises the existing components with temporary synthetic data.

The Phase 9 measured correlation limitation remains operationally relevant: approximately 60.5 seconds for 10,000 synthetic events on the recorded Windows AMD64 environment. The system must not be described as real-time for that workload.

`SysmonEventSource` is a small protocol. The Windows implementation uses the optional pywin32 Event Log API, while tests inject fixture sources and never require Sysmon. The parser accepts XML only, rejects oversized input and DTD/entity declarations, and never executes values found in event fields.

Supported Sysmon IDs are process creation (1), network connection (3), and file creation (11). Unknown IDs are reported as unsupported rather than discarded.

The JSON checkpoint stores the last successfully normalized numeric EventRecordID using an atomic replace. Corrupt checkpoints are quarantined as `.invalid` and surfaced as a typed error. Equal old records are duplicates; lower records are reported as an event-source gap/reset.

## SQLite schema

- `applications`: observed image paths with first/last seen timestamps.
- `ingestion_events`: common provenance, event identity, source, host, timestamp, and deterministic deduplication key.
- `process_events`: process creation details and optional application relationship.
- `network_events`: network fields and nullable process/application relationships.
- `file_events`: file fields and nullable process/application relationships.

Process relationships use the source `process_guid` where available. A network or file event is linked to the latest stored process event with that GUID; no synthetic process identifier is created when the source omits it. Process IDs remain stored as evidence but are not used as stable relationship keys.

The repository uses parameterized SQL, explicit foreign keys, indexes for timestamps, source/event identity, process/application fields, and network destinations, and a transaction around every multi-event insert. Duplicate keys are skipped and returned in an observable insertion result. Any validation failure occurs before insertion, leaving the batch unchanged.

## SignalTrace profiling

`FeatureExtractor` reads stored rows and creates deterministic distributions for Process DNA (launches, executable paths, hashes, parent patterns, child frequencies, and available tree depth), Network DNA (normalized destinations, ports, protocols, connection counts, first/last seen, and determinable local/external scope), File DNA (normalized paths, directories, extensions, and activity counts), Execution DNA (normalized command-line patterns, executable locations, and command categories), Temporal DNA (first/last observations, hour-of-day, and day-of-week activity), and Privilege DNA (only existing integrity/user fields).

Derived normalized paths, destinations, and command patterns are used for comparison while stored provenance remains intact. Missing image paths are counted as unassigned observations rather than assigned to an invented application. Profiles are grouped by normalized executable path, so renamed or reinstalled paths remain distinct identities.

`BaselineBuilder` saves complete versioned profiles in `behavior_profiles` and inspectable category payloads in `behavior_features`. Rebuilding creates the next version. Profiles below the configurable minimum observation count are explicitly `insufficient_data`. There is no threat score, anomaly decision, malware label, or detector in Phase 3.

## Detection

`BehavioralDetector` compares one observation with a compatible `SignalTraceProfile`. Signals cover new child/executable/parent/hash behavior, new destinations/ports/protocols, new file paths/directories/extensions, execution patterns/categories, out-of-baseline time, and reliable privilege changes. Frequency signals require an explicit observed frequency and do not infer frequency from one event.

`StatisticalDetector` trains an `IsolationForest` only from sufficient historical observations and stores the model, configuration, profile version, and feature schema version. The vector schema is ordered and versioned. Incompatible schemas and insufficient baselines return explicit outcomes rather than scoring silently.

The combined score weights deterministic evidence at 65% and statistical deviation at 35%, with a small multi-category evidence adjustment. Severity bands are normal, low, medium, and high; high severity requires both a high score and at least two signals. Scores express behavioral deviation, not malware probability. Results and individual signals are stored in `anomalies` and `detection_signals`.

## Incident correlation

An anomaly is one observation; an incident is a correlated story. `IncidentCorrelator` sorts detections deterministically and groups only same-application evidence within a configurable time window. Same process GUID or parent/child relationships are strong links, overlapping categories are evidence links, and same-application nearby events are medium links. Different applications are never merged merely because timestamps are close.

By default, an incident requires at least two anomalies and two evidence categories, so a single weak deviation does not become a large incident. New related detections update the existing deterministic incident ID; repeated correlation skips already included detection IDs. Incident lifecycle states are `open`, `updated`, `acknowledged`, and `resolved`; no automatic state transitions or remediation are implemented.

Each incident stores a deterministic timeline ordered by timestamp, detection reference, and category. Process nodes preserve GUID/PID/image/parent metadata without inventing missing relationships. The SQLite tables are `incidents`, `incident_events`, and `incident_processes`, with references to detection IDs and indexed application, status, severity, timestamp, and process fields.

## Local explanation

`ExplanationEvidence` is a strict, compact input assembled from incident metadata, signals, process-chain metadata, timeline references, confidence, and version fields. Paths are minimized and raw logs are never passed to a provider. `LocalExplainer` is provider-agnostic; Phase 6 includes a deterministic fallback and a future ONNX adapter boundary, but no model is bundled or downloaded.

`ExplanationService` validates provider output with Pydantic, enforces an output-size limit, checks that evidence sections are grounded in supplied references, and falls back deterministically on unavailable, malformed, oversized, or ungrounded output. Recommendations are investigation-only. AI cannot detect, override scores, create signals, execute commands, or take autonomous action.

## Runtime and benchmarking

`OnnxRuntimeExplainer` loads an explicitly configured local model only. It validates declared input/output names, reports actual runtime/provider availability, and fails explicitly for missing models, unavailable providers, incompatible metadata, or inference errors. `CPUExecutionProvider` is selected only when reported by the installed runtime; other providers are reported only when the runtime returns them.

The benchmark utility measures supplied initialization, warm-up, repeated latency, median, p95, and throughput. CPU and memory metrics remain unset when not reliably measured. It records platform, runtime, provider, model metadata, and timestamp through typed results. No model is downloaded and no theoretical accelerator performance is substituted for measurements.

## Intended system boundary

The planned product flow is:

```text
Windows telemetry
    -> safe parsing and normalization
    -> behavioral features
    -> application behavioral baseline
    -> explainable and statistical drift detection
    -> incident correlation
    -> local AI explanation of structured evidence
    -> REST API and UI
```

The remaining steps are design intent only at this phase. No verified Snapdragon/NPU execution or UI implementation is present.

## Planned data model

SQLite is the initial database choice. The planned entities are `applications`, `process_events`, `network_events`, `file_events`, `behavior_profiles`, `behavior_features`, `anomalies`, and `incidents`.

Relationships, indexes, retention, and migration strategy will be designed before the database is introduced. Event tables should retain application/process identity and timestamps needed to reconstruct behavior timelines while keeping raw sensitive telemetry local.

## Design decisions

- FastAPI and Pydantic are the backend API foundation.
- REST is the initial transport; WebSocket support is deferred until a demonstrated realtime requirement exists.
- The detector, not a language model, will own detection decisions. A future local AI layer may explain structured evidence.
- Local-only operation is the default. Cloud AI/API dependencies are not required.
- Future Snapdragon claims must be backed by measured, reproducible benchmarks; no NPU execution is claimed by this repository.
- ETW is not implemented; the source protocol leaves room for a future event source without changing normalized event consumers.
- Checkpointing remains local JSON for the collector; SQLite stores ingested telemetry and its provenance.
- Retention is opt-in through `DatabaseSettings.retention_days`; expiration deletes matching event rows and leaves newer data untouched.
- SQLite is local-only in this phase. Backup, restore, encryption at rest, migrations, and corruption recovery beyond SQLite's own behavior are operational responsibilities and are not yet implemented.
- Isolation Forest is sensitive to baseline quality, feature representation, contamination, and concept drift; it is not a malware classifier. Legitimate updates, new installations, browser destinations, developer workflows, and seasonal behavior can produce deviations.
- Correlation can produce false positives when unrelated events belong to the same application or when process metadata is incomplete. It is an evidence organization layer, not confirmation of an attack.
- Explanation quality depends on the supplied structured evidence. The deterministic fallback is reliable for grounding but intentionally concise and not a language model.
- This development machine is Windows 11 AMD64 with Python 3.12.5; ONNX Runtime is not installed, so no runtime provider, model, GPU, Snapdragon, or NPU result is claimed. A Snapdragon platform label, when detected, does not mean NPU execution is active.
