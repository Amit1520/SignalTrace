"""Download the SignalTrace development model into the local SignalTrace/models directory.

This script is intentionally not executed by SignalTrace. Run it manually when you
want to acquire the ~3.66 GB CPU INT4 model artifact.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

REPO = "onnx-community/Llama-3.2-3B-Instruct-GENAI-ONNX"
SUBDIR = "cpu_and_mobile/cpu-int4-rtn-block-32-acc-level-4"
ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "models" / "llama-3.2-3b-instruct"


def main() -> None:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise SystemExit(
            "huggingface-hub is required for model acquisition. "
            "Install it in SignalTrace's environment, then rerun this script."
        ) from exc

    with tempfile.TemporaryDirectory(prefix="signaltrace-llama-") as tmp:
        snapshot_download(
            repo_id=REPO,
            local_dir=tmp,
            allow_patterns=[f"{SUBDIR}/*"],
        )
        source = Path(tmp) / SUBDIR
        if not (source / "genai_config.json").is_file():
            raise SystemExit("Downloaded model package is missing genai_config.json")
        DEST.mkdir(parents=True, exist_ok=True)
        for item in source.iterdir():
            target = DEST / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)

    print(f"SignalTrace local GenAI model installed at: {DEST}")


if __name__ == "__main__":
    main()
