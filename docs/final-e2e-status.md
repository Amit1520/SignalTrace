# SignalTrace Final E2E Status

## Included

- Sysmon ingestion, SignalTrace profiling, behavioral detection, incident correlation.
- Structured evidence and deterministic fallback explanation.
- Local Llama 3.2 3B through ONNX Runtime GenAI.
- Local model download and standalone inference helpers.
- SignalTrace provider verification helper.
- CPU generation timing baseline.
- Runtime capability detection and Snapdragon/QNN deployment boundary.

## Important deployment distinction

The distributed source package does not contain the multi-GB model weights and does not claim physical Snapdragon NPU execution. Install the local model package for CPU development, then use the Qualcomm/QNN-prepared GenAI model package on the target Snapdragon Windows machine. NPU execution must be verified on that target before claiming an NPU benchmark.
