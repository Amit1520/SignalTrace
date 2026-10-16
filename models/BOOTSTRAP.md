# SignalTrace Local GenAI Bootstrap

SignalTrace is prepared for a real local ONNX Runtime GenAI model. The source archive does **not** bundle the multi-GB model weights.

## A5 development model

Use the public ONNX Community Llama 3.2 3B Instruct GENAI-ONNX repository, specifically:

`cpu_and_mobile/cpu-int4-rtn-block-32-acc-level-4`

The published CPU INT4 package is about 3.66 GB and contains the `genai_config.json`, tokenizer assets, and ONNX model data required by ONNX Runtime GenAI.

SignalTrace expects those files directly under:

`models/llama-3.2-3b-instruct/`

The helper `scripts/download_local_model.py` performs this acquisition and copies the selected package into the expected SignalTrace directory. It is intentionally manual; SignalTrace never downloads model weights at runtime.

## First local inference

After the model and `onnxruntime-genai` package are available, `scripts/infer_local_model.py` performs a model-only inference check. It does not start the SignalTrace API, collect telemetry, modify SQLite, or run migrations.

## Snapdragon path

The same model family has a Snapdragon-specific ONNX Runtime GenAI deployment path. Current ONNX Runtime documentation lists Llama 3.2 3B as a supported Snapdragon NPU model and requires additional Qualcomm context binaries and ONNX wrapper assets for NPU deployment.

SignalTrace must not report NPU acceleration as verified until the model is actually executed on Snapdragon hardware and the runtime/provider plus benchmark are captured.
