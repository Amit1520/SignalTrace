# SignalTrace local AI models

SignalTrace keeps model artifacts inside this directory so the project remains self-contained.

## Primary model

Target model: **Llama 3.2 3B Instruct**.

The runtime integration uses **ONNX Runtime GenAI** rather than a generic tensor-only ONNX adapter. This is intentional: ONNX Runtime GenAI handles tokenization, autoregressive generation and KV-cache management, and its Snapdragon path supports QNN execution for Llama 3.2 3B.

The model directory used by SignalTrace is:

`models/llama-3.2-3b-instruct/`

It must contain a GenAI model package with at least `genai_config.json` and the model/tokenizer assets referenced by that configuration.

For Snapdragon NPU deployment, use the Qualcomm/ONNX Runtime Snapdragon model assets. The final package is expected to contain the Qualcomm context binaries and ONNX wrapper assets required by the model configuration.

SignalTrace does **not** download models automatically at runtime. This keeps endpoint telemetry local and makes the deployed artifact explicit.

## Configuration

Set:

- `SIGNALTRACE_AI_PROVIDER=onnxruntime-genai`
- `SIGNALTRACE_AI_MODEL_PATH=models/llama-3.2-3b-instruct`

If the provider is left as `deterministic-fallback`, SignalTrace continues to operate without a model.

## Snapdragon target

The same provider interface is used for CPU development and the Snapdragon/QNN model package. Current ONNX Runtime documentation supports Llama 3.2 3B on Snapdragon NPU devices when the required Qualcomm context-binary model assets are present. Hardware acceleration is only claimed for SignalTrace after the runtime reports the provider and a real-device benchmark verifies it.
