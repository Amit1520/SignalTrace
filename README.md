# SignalTrace

SignalTrace is a local behavioral security prototype and investigation aid for Windows. It builds application behavior profiles from Sysmon telemetry and surfaces deviations as evidence for human review. It is not a malware classifier, antivirus, EDR, SIEM, or production-ready security product.

## Demo

[![Watch the SignalTrace demo](https://img.youtube.com/vi/wu0S98uP8aY/hqdefault.jpg)](https://youtu.be/wu0S98uP8aY)

[Watch the demo on YouTube](https://youtu.be/wu0S98uP8aY).

## What it does

- Reads existing Windows Sysmon Operational events through the Windows Event Log API. The collector handles process creation (event 1), network connection (event 3), and file creation (event 11).
- Validates and normalizes supported events, tracks ingestion progress with a JSON checkpoint, and stores normalized telemetry in a local SQLite database.
- Builds versioned application behavior profiles and compares observations against compatible profiles using explainable signals. An optional Isolation Forest contributes a statistical deviation score when there is sufficient historical data.
- Correlates detections into incidents, timelines, and process-chain evidence for investigation.
- Provides a FastAPI backend and a React/TypeScript dashboard. The UI reads the local API; it does not implement a separate detector.
- Produces incident explanations from structured evidence using a deterministic local fallback. An optional ONNX Runtime GenAI provider can be configured with separately supplied model files.

Behavioral deviation scores are not probabilities of malware. New software, legitimate updates, changing destinations, sparse histories, and incomplete telemetry can produce weak signals or false positives. A person must investigate the evidence.

## Architecture

```text
Windows Sysmon Event Log
  -> source abstraction and bounded XML parser
  -> typed normalized events
  -> local SQLite persistence and JSON ingestion checkpoint
  -> feature extraction and versioned behavior profiles
  -> deterministic signals and optional statistical deviation
  -> correlated incidents and structured evidence
  -> deterministic explanation (optional local ONNX Runtime GenAI provider)
  -> FastAPI local API
  -> React/TypeScript dashboard
```

The Python backend is under [`backend/`](backend/); the frontend is under [`frontend/`](frontend/). API metadata and routes are defined in [`backend/api/main.py`](backend/api/main.py). Deployment and privacy details are in [`docs/windows-deployment.md`](docs/windows-deployment.md) and [`docs/security-and-privacy.md`](docs/security-and-privacy.md).

## Requirements

- Windows 10/11 for live Sysmon collection; Python 3.11 or newer for the backend.
- Node.js/npm only when developing or building the frontend.
- Sysmon must be installed and configured separately if live Windows telemetry is required. SignalTrace does not install Sysmon or request elevation.

The backend and synthetic tests can also run without live Sysmon. On unsupported systems or when the event channel/permissions are unavailable, telemetry readiness reports its state rather than fabricating events.

## Setup

From the project root in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

For the Windows Event Log integration, install the Windows extra:

```powershell
python -m pip install -e ".[dev,windows]"
```

Install Sysmon independently using Microsoft's official Sysinternals distribution and an approved configuration. Check whether its channel exists:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

Start the API:

```powershell
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

In another terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The API health endpoint is `http://127.0.0.1:8000/health`; readiness details are at `/health/readiness`. The dashboard uses the local API by default. Set `VITE_API_BASE` when the API is hosted at another address.

The backend exposes local endpoints for readiness, aggregate statistics, telemetry, application profiles, detections, incidents and timelines, incident explanations, AI/runtime status, and starting/stopping and checking continuous ingestion. See the interactive API documentation at `http://127.0.0.1:8000/docs` while the backend is running.

## Configuration and local files

Configuration is read from process environment variables using the `SIGNALTRACE_` prefix. The safe [`.env.example`](.env.example) is a reference template with local defaults and no credentials; it is not automatically loaded by Python settings. For example, set a variable in PowerShell before starting the API:

```powershell
$env:SIGNALTRACE_DATABASE_PATH = "data/signaltrace.sqlite3"
$env:SIGNALTRACE_LOG_LEVEL = "INFO"
```

The main options include:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIGNALTRACE_BACKEND_HOST` | `127.0.0.1` | API bind host |
| `SIGNALTRACE_BACKEND_PORT` | `8000` | API port |
| `SIGNALTRACE_DATABASE_PATH` | `data/signaltrace.sqlite3` | Local SQLite database |
| `SIGNALTRACE_CHECKPOINT_PATH` | `data/signaltrace-sysmon-checkpoint.json` | Sysmon ingestion checkpoint |
| `SIGNALTRACE_SYSMON_CHANNEL` | `Microsoft-Windows-Sysmon/Operational` | Existing Windows Event Log channel |
| `SIGNALTRACE_SYSMON_BATCH_SIZE` | `100` | Collection batch limit |
| `SIGNALTRACE_SYSMON_MAX_XML_BYTES` | `2000000` | Maximum event XML size |
| `SIGNALTRACE_RETENTION_DAYS` | unset | Optional event retention; disabled by default |
| `SIGNALTRACE_AI_PROVIDER` | `onnxruntime-genai` in application settings | `deterministic-fallback` or optional local provider |
| `SIGNALTRACE_AI_MODEL_PATH` | `models/llama-3.2-3b-instruct` | Optional local model directory |
| `SIGNALTRACE_LOG_LEVEL` | `INFO` | Logging level |
| `SIGNALTRACE_CORS_ALLOWED_ORIGINS` | localhost frontend origins | Comma-separated HTTP(S) origins |

New `SIGNALTRACE_*` values take precedence. The application also accepts the corresponding legacy `SECURITYDNA_*` environment variables when the new variable is unset. If an existing `data/securitydna.sqlite3` or `data/securitydna-sysmon-checkpoint.json` is present and its SignalTrace-named counterpart is absent, the default configuration continues using the legacy file in place. Explicitly configured paths are respected. The rename does not move, copy, overwrite, or delete local databases or checkpoints.

Treat telemetry, databases, checkpoints, and any exports as sensitive local data. Do not commit `.env`, credentials, database files, Sysmon exports, checkpoints, downloaded model assets, or model caches. The ignore rules exclude these artifacts; review Git status before staging.

## Tests and validation

Run the Python test suite:

```powershell
python -m pytest
```

Run frontend checks:

```powershell
cd frontend
npm run typecheck
npm run build
```

The deterministic synthetic validation harness can emit a local JSON report:

```powershell
python -m backend.validation.phase9 --output "$env:TEMP\signaltrace-phase9-results.json"
```

The Phase 9 documentation records nine detection/data-quality scenarios and four incident-correlation scenarios passing on its recorded run. It also records synthetic-workload timings of about 468 ms end-to-end for 100 events, 720 ms for 1,000, and 62.2 seconds for 10,000; correlation alone was about 60.5 seconds at 10,000 events. These are historical, machine-specific measurements—not capacity guarantees or real-time claims. The harness uses deterministic synthetic data and temporary databases; it does not use real malware, perform attack simulation, or measure Snapdragon/NPU execution. Full methodology, scenarios, and limitations are in [`docs/validation.md`](docs/validation.md).

## Privacy and security boundaries

- Sysmon collection is read-only and limited to the configured existing event channel. SignalTrace does not install services, modify the registry, elevate privileges, or execute values found in telemetry.
- Parsed events, profiles, and incidents are stored locally in SQLite. No backend telemetry upload, cloud processing, cloud AI, or remote backup is implemented.
- The dashboard defaults to the local API, but its API base can be changed; keep it on a trusted local address for local-only use. Default CORS origins are local development origins.
- The explanation provider receives compact structured incident evidence rather than raw Sysmon logs. Model output does not perform detection or response and is validated before use; deterministic fallback remains available when a local model is unavailable.
- Retention is disabled unless explicitly configured. Databases are not encrypted by the application.

## Limitations

SignalTrace is a prototype, not a production security control. It does not provide malware-classification accuracy, confirmed threat attribution, automated response/remediation, access control, encryption at rest, automated backups, or database migration tooling. Behavioral changes can be legitimate and require human review. The available validation is synthetic and does not establish effectiveness against real malware or operational Windows workloads.

The ONNX Runtime GenAI integration is optional and requires a separately supplied compatible model package. Model weights are not bundled or downloaded automatically. Snapdragon, QNN, GPU, and NPU execution have not been verified by the checked-in validation results; do not infer accelerator support from configuration or hardware detection alone.

## Further documentation

- [Architecture](docs/architecture.md)
- [Windows deployment](docs/windows-deployment.md)
- [Security and privacy](docs/security-and-privacy.md)
- [Local AI boundary](docs/local-ai.md)
- [Validation methodology and results](docs/validation.md)
- [Development roadmap](docs/development-roadmap.md)
