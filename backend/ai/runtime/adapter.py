import time
from pathlib import Path
from typing import Any

from ..models import Explanation, ExplanationEvidence
from ..provider import LocalExplainer, ModelInferenceError, ModelUnavailableError
from .capabilities import detect_runtime_capabilities
from .models import ModelMetadata, RuntimeCapabilities, RuntimeStatus


class OnnxRuntimeExplainer(LocalExplainer):
    provider = "onnxruntime"

    def __init__(
        self,
        model_path: Path,
        metadata: ModelMetadata,
        requested_provider: str | None = None,
        ort_module=None,
    ) -> None:
        self.model_path = model_path
        self.metadata = metadata.model_copy(update={"model_path": str(model_path), "model_size_bytes": model_path.stat().st_size if model_path.is_file() else None})
        self.capabilities: RuntimeCapabilities = detect_runtime_capabilities(requested_provider, ort_module)
        self._ort = ort_module
        self.session = None
        self.model_identifier = f"{metadata.name}:{metadata.version}"
        if not model_path.is_file():
            raise ModelUnavailableError(f"local model is unavailable: {model_path}")
        if self.capabilities.status is not RuntimeStatus.AVAILABLE:
            raise ModelUnavailableError(self.capabilities.error or "ONNX Runtime is unavailable")
        try:
            self.session = self._create_session()
            self._validate_io()
            self.metadata = self.metadata.model_copy(update={"compatibility_status": "compatible"})
        except ModelUnavailableError:
            raise
        except Exception as error:
            raise ModelInferenceError(f"ONNX model initialization failed: {error}") from error

    def _create_session(self):
        ort = self._ort
        if ort is None:
            import onnxruntime as ort
        providers = [self.capabilities.execution_provider] if self.capabilities.execution_provider else None
        return ort.InferenceSession(str(self.model_path), providers=providers)

    def _validate_io(self) -> None:
        if self.session is None:
            raise ModelUnavailableError("ONNX session is not initialized")
        inputs = self.session.get_inputs()
        outputs = self.session.get_outputs()
        expected_inputs = self.metadata.input_requirements.get("names", [])
        expected_outputs = self.metadata.output_requirements.get("names", [])
        actual_inputs = [item.name for item in inputs]
        actual_outputs = [item.name for item in outputs]
        if expected_inputs and actual_inputs != expected_inputs:
            raise ModelInferenceError("ONNX input names do not match model metadata")
        if expected_outputs and actual_outputs != expected_outputs:
            raise ModelInferenceError("ONNX output names do not match model metadata")

    def explain_incident(self, evidence: ExplanationEvidence) -> Explanation:
        raise ModelInferenceError("ONNX text explanation execution requires a compatible local model adapter")

    def run_tensor(self, inputs: dict[str, Any]) -> list[Any]:
        if self.session is None:
            raise ModelUnavailableError("ONNX session is not initialized")
        try:
            return self.session.run(None, inputs)
        except Exception as error:
            raise ModelInferenceError(f"ONNX inference failed: {error}") from error

    def input_shapes(self) -> list[Any]:
        return [item.shape for item in self.session.get_inputs()] if self.session else []

    def output_shapes(self) -> list[Any]:
        return [item.shape for item in self.session.get_outputs()] if self.session else []

    def timed_initialization_ms(self) -> float:
        started = time.perf_counter()
        self._create_session()
        return (time.perf_counter() - started) * 1000
