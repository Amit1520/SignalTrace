import platform
import sys
from importlib import import_module

from .models import RuntimeCapabilities, RuntimeStatus


def detect_runtime_capabilities(requested_provider: str | None = None, ort_module=None) -> RuntimeCapabilities:
    system = platform.system()
    capabilities = RuntimeCapabilities(
        platform=platform.platform(),
        architecture=platform.machine(),
        windows_version=platform.version() if system == "Windows" else None,
        requested_provider=requested_provider,
        status=RuntimeStatus.UNAVAILABLE,
    )
    if system == "Windows" and _is_snapdragon_platform():
        capabilities.hardware_label = "Snapdragon platform detected"
    try:
        ort = ort_module or import_module("onnxruntime")
    except (ImportError, ModuleNotFoundError) as error:
        capabilities.error = "onnxruntime is not installed"
        return capabilities
    try:
        capabilities.runtime_version = ort.__version__
        capabilities.available_providers = list(ort.get_available_providers())
        if not capabilities.available_providers:
            capabilities.status = RuntimeStatus.UNAVAILABLE
            capabilities.error = "ONNX Runtime reported no execution providers"
            return capabilities
        if requested_provider is not None:
            if requested_provider not in capabilities.available_providers:
                capabilities.error = f"execution provider unavailable: {requested_provider}"
                return capabilities
            capabilities.execution_provider = requested_provider
        elif "CPUExecutionProvider" in capabilities.available_providers:
            capabilities.execution_provider = "CPUExecutionProvider"
        capabilities.device = capabilities.execution_provider or "not selected"
        capabilities.status = RuntimeStatus.AVAILABLE
    except Exception as error:
        capabilities.status = RuntimeStatus.ERROR
        capabilities.error = f"runtime capability detection failed: {error}"
    return capabilities


def _is_snapdragon_platform() -> bool:
    machine = platform.machine().lower()
    processor = platform.processor().lower()
    return "arm" in machine and ("qualcomm" in processor or "snapdragon" in processor)


def platform_snapshot() -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
        "processor": platform.processor(),
    }
