Set-Location (Join-Path $PSScriptRoot "..")
$backendHost = if ($env:SIGNALTRACE_BACKEND_HOST) { $env:SIGNALTRACE_BACKEND_HOST } elseif ($env:SECURITYDNA_BACKEND_HOST) { $env:SECURITYDNA_BACKEND_HOST } else { "127.0.0.1" }
$backendPort = if ($env:SIGNALTRACE_BACKEND_PORT) { $env:SIGNALTRACE_BACKEND_PORT } elseif ($env:SECURITYDNA_BACKEND_PORT) { $env:SECURITYDNA_BACKEND_PORT } else { "8000" }
python -m uvicorn backend.api.main:app --host $backendHost --port $backendPort
