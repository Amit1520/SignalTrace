from pathlib import Path


def preserve_legacy_default(
    path: Path,
    *,
    current_path: Path,
    legacy_path: Path,
) -> Path:
    if path == current_path and not current_path.exists() and legacy_path.exists():
        return legacy_path
    return path
