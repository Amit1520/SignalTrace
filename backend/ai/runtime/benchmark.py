import os
import platform
import statistics
import time
from datetime import datetime, timezone
from typing import Callable, Any

from .capabilities import detect_runtime_capabilities, platform_snapshot
from .models import BenchmarkResult, ModelMetadata, RuntimeMetrics, RuntimeStatus


def benchmark_inference(
    inference: Callable[[], Any],
    model: ModelMetadata,
    iterations: int = 20,
    warmup_iterations: int = 3,
    capabilities=None,
    initialize: Callable[[], Any] | None = None,
) -> BenchmarkResult:
    if iterations < 1 or warmup_iterations < 0:
        raise ValueError("iterations must be positive and warmup_iterations cannot be negative")
    capabilities = capabilities or detect_runtime_capabilities()
    started_at = datetime.now(timezone.utc)
    if capabilities.status is not RuntimeStatus.AVAILABLE:
        return BenchmarkResult(
            started_at=started_at,
            capabilities=capabilities,
            model=model,
            metrics=RuntimeMetrics(iterations=0, warmup_iterations=0),
            status=capabilities.status,
            error=capabilities.error or "runtime unavailable",
        )
    try:
        initialization_ms = None
        if initialize is not None:
            init_started = time.perf_counter()
            initialize()
            initialization_ms = (time.perf_counter() - init_started) * 1000
        warmup_latency_ms = None
        for _ in range(warmup_iterations):
            warmup_started = time.perf_counter()
            inference()
            warmup_latency_ms = (time.perf_counter() - warmup_started) * 1000
        samples = []
        for _ in range(iterations):
            begin = time.perf_counter()
            inference()
            samples.append((time.perf_counter() - begin) * 1000)
        ordered = sorted(samples)
        p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
        median = statistics.median(samples)
        metrics = RuntimeMetrics(
            initialization_ms=initialization_ms,
            warmup_latency_ms=warmup_latency_ms,
            median_latency_ms=median,
            p95_latency_ms=ordered[p95_index],
            throughput_per_second=1000 / median if median > 0 else None,
            cpu_percent=_process_cpu_percent(),
            memory_mb=_process_memory_mb(),
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        )
        return BenchmarkResult(started_at=started_at, capabilities=capabilities, model=model, metrics=metrics, status=RuntimeStatus.AVAILABLE)
    except Exception as error:
        return BenchmarkResult(
            started_at=started_at,
            capabilities=capabilities,
            model=model,
            metrics=RuntimeMetrics(iterations=0, warmup_iterations=warmup_iterations),
            status=RuntimeStatus.ERROR,
            error=f"benchmark inference failed: {error}",
        )


def _process_cpu_percent() -> float | None:
    return None


def _process_memory_mb() -> float | None:
    return None
