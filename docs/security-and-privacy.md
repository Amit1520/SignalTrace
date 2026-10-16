# Security and Privacy

SignalTrace is designed for local Windows operation and treats telemetry as sensitive private data.

## Principles

- Collect only the telemetry needed for an explicitly defined behavioral feature.
- Run with least privilege and document any permission required by a collector.
- Validate and safely parse all external telemetry before it reaches application logic.
- Never construct shell commands from telemetry or UI input.
- Do not provide arbitrary command execution through the API or future UI.
- Keep telemetry, profiles, and incident evidence local by default.
- Make retention configurable and provide a documented deletion path when storage is introduced.
- Do not require a cloud AI service or cloud API.
- Keep local AI explanations subordinate to structured detector evidence.

## Phase 10 implementation

Phase 1 reads an existing Windows Sysmon Operational channel through the read-only Event Log API. It does not install Sysmon, alter the registry, load drivers, change kernel state, or request elevation. On non-Windows systems, the Windows source reports that Sysmon is unavailable and fixture tests use injected sources.

XML is size-limited, rejects DTD/entity declarations, and is parsed as data. Command lines, paths, scripts, and payloads are never passed to a shell or otherwise executed. Normalized command-line values are retained only when present in the event because they are part of behavioral evidence; applications should avoid logging them unnecessarily.

The local JSON checkpoint is written with a temporary file and atomic replacement. Invalid checkpoints are quarantined and reported. Malformed events, unsupported IDs, duplicates, source gaps/resets, permission failures, and unavailable sources have distinct typed error codes.

Normalized events are persisted only to a local SQLite file. SQL statements are fixed application statements with bound parameters; telemetry, API input, and user input cannot supply SQL or table names. Command lines, paths, hashes, host names, and network data are sensitive and are stored only as event evidence, not emitted in routine database-layer messages.

Retention is disabled by default. When `retention_days` is explicitly configured, `delete_expired` removes only event rows whose normalized timestamp is older than the calculated cutoff. It does not delete newer events and does not silently apply a default retention period. Applications rows are retained as historical references until a later cleanup policy is defined.

The database is local-only and no replication or cloud backup is provided. Backups must be handled as sensitive telemetry exports. SQLite file loss or corruption recovery, encryption at rest, migrations, and secure backup rotation are not yet implemented.

The profiling layer reads persisted normalized rows and computes descriptive frequency distributions only. It never executes command lines, opens file contents, resolves network connections, or transmits telemetry. Derived normalized paths, destinations, and command patterns are used for comparison; raw event provenance remains in the event tables.

Profile identity is based on a normalized observed executable path. Missing identity is reported as unassigned rather than fabricated. Renamed or reinstalled paths remain distinct identities. Privilege DNA uses only existing integrity/user telemetry and marks it unavailable when absent. Profiles below the minimum observation threshold are marked `insufficient_data`; this is data quality, not a threat or anomaly score.

Detection compares observations to compatible profiles and records evidence locally. It does not execute commands, terminate processes, delete or quarantine files, block network activity, or perform autonomous remediation. Isolation Forest is trained only from sufficient historical observations, uses deterministic test configuration, and stores its feature schema/model metadata for compatibility checks.

Behavioral deviation scores are not malware probabilities. Legitimate software updates, first-seen applications, changing browser destinations, developer tools, sparse histories, and time-based behavior changes can create false positives. An insufficient or incompatible baseline produces an explicit non-score outcome.

Incident correlation groups behavioral deviation evidence locally using application identity, a configurable time window, process GUID and parent/child relationships, and overlapping categories. It does not declare an attack confirmed. Incomplete telemetry can leave process nodes orphaned or without GUIDs; those values remain missing rather than being fabricated. Timeline and process-chain data are stored as references and structured metadata, not copied raw telemetry blobs.

The incident API is read-only: `GET /incidents`, `GET /incidents/{incident_id}`, and `GET /incidents/{incident_id}/timeline`. No endpoint terminates processes, deletes or quarantines files, blocks network activity, executes commands, or changes lifecycle state automatically.

The explanation layer is local-only and receives only strict structured evidence. It minimizes paths, excludes raw logs and unnecessary telemetry, validates model output, rejects unsupported claims, and uses a deterministic fallback when a provider is unavailable or malformed. The current ONNX adapter is only an interface boundary and does not claim inference, Snapdragon, or NPU execution.

Phase 7 keeps model paths explicit and local. ONNX Runtime is optional, no model is downloaded automatically, and provider names are accepted only from the installed runtime's capability list. Model inputs and outputs are validated; model output remains untrusted text and is never executed. Benchmarking has no network path and reports unavailable metrics as unavailable.

The dashboard is a visualization layer over local API responses. It polls only the local configured API, minimizes sensitive paths in visible process cards, and does not expose command lines or raw telemetry by default. Missing backend data is presented as unavailable or waiting rather than replaced with demo incidents. No cloud analytics or telemetry upload is used.

Configuration uses safe relative local paths and explicit `SIGNALTRACE_*` environment overrides. No secrets are required. Readiness does not expose telemetry contents. Logging is limited to structured component messages and does not dump command lines, file contents, or raw event payloads.

The deployment review found no subprocess or shell execution, no external telemetry transmission, no privilege escalation, and no SQL built from telemetry. XML parsing remains size-limited and rejects DTD/entity declarations. Detector model reload now restricts pickle globals to known numerical/ML namespaces; database files are still local sensitive state and should not be treated as trusted interchange files.

Explanations are not detections and cannot override anomaly scores or incident evidence. Recommendations are limited to investigation steps such as reviewing a process, verifying a destination, inspecting a signature, or comparing a recent software update. No model output is executed.

Phase 10 does not yet implement access control, encryption at rest, automated backups, migrations, or full operational log redaction. It does not transmit telemetry to external services. These controls must be designed with future persistence and API surfaces rather than assumed from this collector.

No malware or attack simulator is included. Future suspicious-behavior tests will use safe controlled simulations.
