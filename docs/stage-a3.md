# Stage A3 — Local GenAI provider

SignalTrace now contains the implementation boundary for a real local generative model.

## What changed

- Added `backend/ai/genai_provider.py` using ONNX Runtime GenAI.
- Added `backend/ai/factory.py` for fail-safe provider construction.
- Wired the incident explanation API to the configured local provider.
- Added `/ai/model` metadata for the configured model slot instead of always reporting `none/unconfigured`.
- Added an optional `genai` dependency group in `pyproject.toml`.
- Added `models/llama-3.2-3b-instruct/` as SignalTrace's model slot.
- Added local-AI documentation and configuration guidance.
- Preserved the deterministic fallback and existing grounding validation.

## Runtime strategy

The provider uses ONNX Runtime GenAI because its generation API handles the LLM loop and it has a documented Qualcomm QNN path. The same provider contract can therefore use a CPU model during development and a Snapdragon-prepared model package for the final Windows-on-Snapdragon deployment.

## Current state

The source integration is ready, but the uploaded SignalTrace archive did not contain the large model artifact. Therefore this change does **not** claim that local LLM inference is already running. The next step is to place/build the actual Llama 3.2 3B GenAI model package inside the SignalTrace model slot and then explicitly verify inference.
