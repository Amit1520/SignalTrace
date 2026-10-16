"""Construction of the configured local AI provider."""

from __future__ import annotations

from backend.config import SignalTraceSettings

from .genai_provider import OnnxRuntimeGenAIExplainer
from .provider import LocalExplainer, ModelInferenceError, ModelUnavailableError


def create_configured_explainer(settings: SignalTraceSettings | None = None) -> LocalExplainer | None:
    settings = settings or SignalTraceSettings()
    provider = settings.ai_provider.strip().lower()

    if provider in {"", "deterministic-fallback", "fallback", "none"}:
        return None

    if provider in {"onnxruntime-genai", "onnx-genai", "genai"}:
        if settings.ai_model_path is None:
            return None
        try:
            return OnnxRuntimeGenAIExplainer(settings.ai_model_path)
        except (ModelUnavailableError, ModelInferenceError):
            # Provider construction is intentionally fail-safe: the API should
            # retain SignalTrace's deterministic explanation rather than fail closed
            # when a local model package is absent or incompatible.
            return None

    return None
