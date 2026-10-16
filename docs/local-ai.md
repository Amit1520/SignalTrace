# SignalTrace Local AI

## Stage A implementation

SignalTrace's local explanation layer now has a real ONNX Runtime GenAI provider boundary. The provider consumes only `ExplanationEvidence` and returns SignalTrace's existing structured `Explanation` schema.

### Configuration

```text
SIGNALTRACE_AI_PROVIDER=onnxruntime-genai
SIGNALTRACE_AI_MODEL_PATH=models/llama-3.2-3b-instruct
```

Without a configured model, the deterministic fallback remains active.

### Snapdragon deployment path

The provider is intentionally based on ONNX Runtime GenAI rather than a custom LLM engine. ONNX Runtime GenAI supports Llama-family models and the Qualcomm QNN execution provider. The Snapdragon model package contains the model assets and runtime configuration required for NPU execution.

The development CPU path and Snapdragon path therefore share the same SignalTrace `LocalExplainer` contract. The final Snapdragon/NPU claim must be backed by actual device/provider detection and measured latency.

### Security boundary

- The model receives structured evidence, not raw Sysmon logs.
- The model does not perform detection.
- The model cannot execute commands.
- The model cannot change detection scores.
- Invalid or ungrounded output falls back to the deterministic explanation.
