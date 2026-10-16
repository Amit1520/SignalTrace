from pathlib import Path

import pytest

from backend.ai.models import ExplanationEvidence
from backend.ai.runtime.adapter import OnnxRuntimeExplainer
from backend.ai.runtime.benchmark import benchmark_inference
from backend.ai.runtime.capabilities import detect_runtime_capabilities
from backend.ai.runtime.models import ModelMetadata, RuntimeCapabilities, RuntimeStatus
from backend.ai.provider import ModelInferenceError, ModelUnavailableError


class FakeIO:
    def __init__(self, name: str, shape: list[int | str]):
        self.name = name
        self.shape = shape


class FakeSession:
    def __init__(self, path: str, providers=None):
        self.path = path
        self.providers = providers

    def get_inputs(self):
        return [FakeIO("input", [1, 4])]

    def get_outputs(self):
        return [FakeIO("output", [1, 2])]

    def run(self, outputs, inputs):
        return [[1, 0]]


class FakeOrt:
    __version__ = "1.20.test"

    @staticmethod
    def get_available_providers():
        return ["CPUExecutionProvider"]

    InferenceSession = FakeSession


def metadata() -> ModelMetadata:
    return ModelMetadata(
        name="test-explainer",
        version="1",
        opset=17,
        input_requirements={"names": ["input"]},
        output_requirements={"names": ["output"]},
        precision="fp32",
        context_limit=128,
        license_source="test fixture",
    )


def test_runtime_capabilities_detect_cpu_and_no_false_npu_claim() -> None:
    capabilities = detect_runtime_capabilities(ort_module=FakeOrt)

    assert capabilities.status is RuntimeStatus.AVAILABLE
    assert capabilities.execution_provider == "CPUExecutionProvider"
    assert capabilities.npu_verified is False


def test_unavailable_runtime_and_provider_are_explicit() -> None:
    unavailable = detect_runtime_capabilities(ort_module=type("NoProviders", (), {"__version__": "1", "get_available_providers": staticmethod(lambda: [])}))
    provider = detect_runtime_capabilities("FakeExecutionProvider", FakeOrt)

    assert unavailable.status is RuntimeStatus.UNAVAILABLE
    assert provider.status is RuntimeStatus.UNAVAILABLE
    assert "unavailable" in provider.error


def test_missing_model_is_explicit(tmp_path: Path) -> None:
    with pytest.raises(ModelUnavailableError):
        OnnxRuntimeExplainer(tmp_path / "missing.onnx", metadata(), ort_module=FakeOrt)


def test_model_io_validation_and_tensor_call(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"fixture")
    adapter = OnnxRuntimeExplainer(model_path, metadata(), ort_module=FakeOrt)

    assert adapter.capabilities.execution_provider == "CPUExecutionProvider"
    assert adapter.input_shapes() == [[1, 4]]
    assert adapter.output_shapes() == [[1, 2]]
    assert adapter.run_tensor({"input": [[0, 0, 0, 0]]}) == [[1, 0]]


def test_model_io_mismatch_fails(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"fixture")
    invalid = metadata().model_copy(update={"input_requirements": {"names": ["wrong"]}})

    with pytest.raises(ModelInferenceError):
        OnnxRuntimeExplainer(model_path, invalid, ort_module=FakeOrt)


def test_benchmark_statistics_are_measured_and_deterministic_configuration() -> None:
    capabilities = RuntimeCapabilities(
        platform="test", architecture="test", status=RuntimeStatus.AVAILABLE,
        available_providers=["CPUExecutionProvider"], execution_provider="CPUExecutionProvider",
    )
    result = benchmark_inference(
        lambda: 1 + 1,
        metadata(),
        iterations=5,
        warmup_iterations=2,
        capabilities=capabilities,
        initialize=lambda: None,
    )

    assert result.status is RuntimeStatus.AVAILABLE
    assert result.metrics.iterations == 5
    assert result.metrics.warmup_iterations == 2
    assert result.metrics.median_latency_ms is not None
    assert result.metrics.p95_latency_ms is not None
    assert result.metrics.throughput_per_second is not None
    assert result.metrics.cpu_percent is None
    assert result.metrics.memory_mb is None
    assert result.metrics.warmup_latency_ms is not None
    assert result.metrics.initialization_ms is not None


def test_unavailable_benchmark_does_not_fabricate_results() -> None:
    capabilities = RuntimeCapabilities(platform="test", architecture="test", status=RuntimeStatus.UNAVAILABLE, error="not installed")
    result = benchmark_inference(lambda: 1, metadata(), capabilities=capabilities)

    assert result.status is RuntimeStatus.UNAVAILABLE
    assert result.metrics.iterations == 0
    assert result.metrics.median_latency_ms is None


def test_snapdragon_detection_is_label_only_when_mocked(monkeypatch) -> None:
    monkeypatch.setattr("backend.ai.runtime.capabilities.platform.machine", lambda: "ARM64")
    monkeypatch.setattr("backend.ai.runtime.capabilities.platform.processor", lambda: "Qualcomm Snapdragon")
    monkeypatch.setattr("backend.ai.runtime.capabilities.platform.system", lambda: "Windows")
    capabilities = detect_runtime_capabilities(ort_module=FakeOrt)

    assert capabilities.hardware_label == "Snapdragon platform detected"
    assert capabilities.npu_verified is False
    assert capabilities.execution_provider == "CPUExecutionProvider"
