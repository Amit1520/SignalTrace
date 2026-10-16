# Windows Deployment

SignalTrace is a local behavioral integrity monitor and explanation surface for Windows 10/11. It is not an antivirus, EDR, SIEM, cloud SOC, or autonomous remediation tool.

## Prerequisites

- Windows 10 or Windows 11.
- Python 3.11 or newer.
- Node.js/npm for the frontend.
- Sysmon installed separately from Microsoft Sysinternals when Windows telemetry is required.
- An approved Sysmon configuration.
- Optional `pywin32` for the read-only Event Log source.
- Optional ONNX Runtime only when a compatible local model is explicitly available.

SignalTrace does not install Sysmon, modify services or the registry, load drivers, request elevation, download models, or require cloud access.

## Install

From PowerShell at the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,windows]"
```

For development without Windows Event Log support:

```powershell
python -m pip install -e ".[dev]"
```

The optional ONNX adapter can be installed separately:

```powershell
python -m pip install -e ".[onnx]"
```

No model is downloaded automatically.

## Configuration

Copy `.env.example` to `.env` or set process environment variables. Defaults use relative local paths:

- `SIGNALTRACE_DATABASE_PATH`
- `SIGNALTRACE_CHECKPOINT_PATH`
- `SIGNALTRACE_BACKEND_HOST` / `SIGNALTRACE_BACKEND_PORT`
- `SIGNALTRACE_SYSMON_CHANNEL`, batch size, and XML limit
- profile, detection, correlation, and retention settings
- `SIGNALTRACE_AI_MODEL_PATH` and provider label
- `SIGNALTRACE_LOG_LEVEL`
- `SIGNALTRACE_CORS_ALLOWED_ORIGINS` for comma-separated local frontend origins

Do not commit `.env` or secrets. SQLite and checkpoint parent directories are created on first use. Retention is disabled unless explicitly configured.

By default, CORS allows only `http://localhost:5173` and `http://127.0.0.1:5173`. Credentials and wildcard origins are disabled. Keep any override limited to trusted local development origins.

## Sysmon verification

Install and configure Sysmon independently, then verify the channel without changing it:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

If Sysmon, pywin32, the channel, or access permission is unavailable, readiness reports telemetry as unavailable. The API, SQLite initialization, deterministic fallback explanation, and non-telemetry endpoints remain usable.

## Run the backend

```powershell
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

The repository helper uses `SIGNALTRACE_BACKEND_HOST` and `SIGNALTRACE_BACKEND_PORT` when set:

```powershell
.\scripts\run_backend.ps1
```

Check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/health/readiness
```

`/health` preserves the basic compatibility response. `/health/readiness` reports actual API, database, telemetry, profile, local AI, and runtime states.

## Run the frontend

In a second PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

Or use:

```powershell
.\scripts\run_frontend.ps1
```

For a production build:

```powershell
npm run typecheck
npm run build
```

The frontend defaults to `http://127.0.0.1:8000`; set `VITE_API_BASE` if the backend is hosted at another local address.

## End-to-end smoke test

```powershell
C:/Python312/python.exe -m backend.smoke
```

The smoke test uses temporary deterministic synthetic events, exercises normalization-compatible models, SQLite, profiling, detection, correlation, explanation, and API reads, then cleans up its database. It does not use Sysmon or real malware.

## Recovery and operational limits

- Repeated startup is safe because SQLite schema creation is idempotent.
- Corrupt JSON checkpoints are quarantined with an `.invalid` suffix and surfaced.
- Malformed events are classified by the parser and do not crash the collector loop.
- Shutdown is process-local; SQLite commits are transaction-scoped.
- Back up SQLite only as sensitive local telemetry data. Automated backup, encryption, and migration tooling are not implemented.
- Phase 9 measured approximately 60.5 seconds for 10,000 synthetic events in correlation on one Windows AMD64 machine. Do not describe that workload as real-time.

## Troubleshooting

- **Telemetry unavailable:** verify Windows, Sysmon channel, pywin32, and read access. No elevation is performed automatically.
- **Database error:** verify the configured parent directory is writable and that the SQLite file is not locked by another process.
- **Frontend cannot load data:** start the backend and check `VITE_API_BASE`; the UI intentionally shows an unavailable state instead of fake data.
- **Local AI unavailable:** deterministic fallback explanations remain available. No cloud provider is used.
- **Runtime unavailable:** `/ai/runtime` reports the installed state. Snapdragon/NPU execution is not implied by hardware detection.
