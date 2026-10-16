"""Manual local Llama GenAI inference and CPU baseline for SignalTrace.

This script does not start the SignalTrace server and does not touch telemetry or
the SQLite database. It only loads the configured local model and measures
generation time.
"""
from __future__ import annotations

import time
from pathlib import Path


def main() -> None:
    import onnxruntime_genai as og

    model_dir = Path(__file__).resolve().parents[1] / "models" / "llama-3.2-3b-instruct"
    if not (model_dir / "genai_config.json").is_file():
        raise SystemExit(
            f"Model package not found: {model_dir}\n"
            "Run: python scripts\\download_local_model.py"
        )

    model = og.Model(str(model_dir))
    tokenizer = og.Tokenizer(model)
    prompt = (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
        "You are a concise local cybersecurity analyst.\n"
        "<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
        "Explain why an endpoint process launching PowerShell from an unusual parent may be anomalous. "
        "Use only this supplied fact.\n"
        "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
    )
    input_tokens = tokenizer.encode(prompt)
    params = og.GeneratorParams(model)
    params.set_search_options(
        max_length=min(384, len(input_tokens) + 320),
        temperature=0.0,
        top_p=1.0,
        do_sample=False,
    )
    generator = og.Generator(model, params)
    generator.append_tokens(input_tokens)
    stream = tokenizer.create_stream()
    chunks: list[str] = []
    start_time = time.perf_counter()
    while not generator.is_done():
        generator.generate_next_token()
        chunks.append(stream.decode(generator.get_next_tokens()[0]))
    elapsed = time.perf_counter() - start_time
    output = "".join(chunks).strip()

    # get_sequence(0) is supported by current ORT GenAI releases; keep the
    # benchmark robust if a future release changes that helper.
    try:
        output_tokens = len(generator.get_sequence(0))
    except Exception:
        output_tokens = len(tokenizer.encode(output))
    generated_tokens = max(0, output_tokens - len(input_tokens))

    print(output)
    print(f"\nInput tokens: {len(input_tokens)}")
    print(f"Output tokens: {generated_tokens}")
    print(f"Generation time: {elapsed:.3f} seconds")
    if elapsed > 0:
        print(f"Generation throughput: {generated_tokens / elapsed:.2f} tokens/sec")


if __name__ == "__main__":
    main()
