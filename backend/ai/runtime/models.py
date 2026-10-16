from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuntimeStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    NOT_VERIFIED = "not_verified"


class ModelMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    format: str = "onnx"
    opset: int | None = None
    input_requirements: dict[str, Any] = Field(default_factory=dict)
    output_requirements: dict[str, Any] = Field(default_factory=dict)
    precision: str | None = None
    context_limit: int | None = Field(default=None, ge=1)
    license_source: str | None = None
    model_path: str | None = None
    model_size_bytes: int | None = Field(default=None, ge=0)
    compatibility_status: str = "unknown"


class RuntimeCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runtime_name: str = "onnxruntime"
    runtime_version: str | None = None
    available_providers: list[str] = Field(default_factory=list)
    requested_provider: str | None = None
    execution_provider: str | None = None
    device: str | None = None
    platform: str
    architecture: str
    windows_version: str | None = None
    hardware_label: str | None = None
    npu_verified: bool = False
    status: RuntimeStatus
    error: str | None = None


class RuntimeMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    initialization_ms: float | None = Field(default=None, ge=0)
    warmup_latency_ms: float | None = Field(default=None, ge=0)
    median_latency_ms: float | None = Field(default=None, ge=0)
    p95_latency_ms: float | None = Field(default=None, ge=0)
    throughput_per_second: float | None = Field(default=None, ge=0)
    cpu_percent: float | None = Field(default=None, ge=0)
    memory_mb: float | None = Field(default=None, ge=0)
    iterations: int = Field(ge=0)
    warmup_iterations: int = Field(ge=0)


class BenchmarkResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    started_at: datetime
    capabilities: RuntimeCapabilities
    model: ModelMetadata
    metrics: RuntimeMetrics
    status: RuntimeStatus
    error: str | None = None
