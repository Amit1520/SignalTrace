# SignalTrace Final E2E Setup

## 1. Open the project root
Run the following commands from the extracted project root, where `pyproject.toml` is located.

## 2. Create and activate environment (PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,windows,genai,model-download]"
```

## 3. Model
The ZIP intentionally does NOT contain the ~3.6 GB Llama model.

Required path:
`models\llama-3.2-3b-instruct\`

It must contain `genai_config.json` and the other model/tokenizer/ONNX assets.

Acquire it:
```powershell
python scripts\download_local_model.py
```

Or copy your already downloaded working package into that exact folder.

## 4. Verify standalone local inference
```powershell
python scripts\infer_local_model.py
```

## 5. Verify SignalTrace -> Llama integration
```powershell
python scripts\verify_local_ai.py
```

## 6. Run tests
```powershell
python -m pytest -q
```

## 7. Run deterministic smoke test
```powershell
python -m backend.smoke
```

## 8. Start backend
```powershell
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

In another PowerShell:
```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/health/readiness
Invoke-RestMethod http://127.0.0.1:8000/ai/model
Invoke-RestMethod http://127.0.0.1:8000/ai/runtime
```

## 9. Start Sysmon ingestion
```powershell
Invoke-RestMethod -Method POST "http://127.0.0.1:8000/ingestion/start?interval_seconds=5"
Invoke-RestMethod http://127.0.0.1:8000/ingestion/status
```

## 10. Frontend
Open a second terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open:
`http://127.0.0.1:5173`

## 11. Snapdragon/QNN
The normal Windows CPU model is not proof of Snapdragon NPU execution.
For Snapdragon deployment, replace/use a Qualcomm/QNN-compatible GenAI model package and the corresponding ONNX Runtime/QNN runtime supported by the target Snapdragon environment. Verify the actual execution provider/device before claiming NPU execution.

Do not claim an NPU benchmark until it is measured on supported Snapdragon hardware.

## 12. Existing configuration and local data
New settings use the `SIGNALTRACE_` environment-variable prefix. Existing `SECURITYDNA_*` variables continue to work when the matching `SIGNALTRACE_*` variable is unset; prefer the new prefix for new configurations.

The default paths are now `data/signaltrace.sqlite3` and `data/signaltrace-sysmon-checkpoint.json`. If the corresponding legacy database or checkpoint already exists and the new path does not, SignalTrace continues using that existing file in place. It does not move, copy, overwrite, or delete local data. An explicitly configured path remains authoritative.
