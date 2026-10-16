import json
import os
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from .errors import CheckpointCorruptError


@dataclass(frozen=True)
class Checkpoint:
    last_successful_record_id: str | None = None


class JsonCheckpointStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load_or_reset(self) -> Checkpoint:
        if not self.path.exists():
            return Checkpoint()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            record_id = payload["last_successful_record_id"]
            if record_id is not None and (
                not isinstance(record_id, str) or not record_id.isdigit()
            ):
                raise ValueError("record ID must be a numeric string")
            return Checkpoint(last_successful_record_id=record_id)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self._quarantine_corrupt_file()
            raise CheckpointCorruptError(
                f"checkpoint was invalid and has been reset: {self.path}"
            ) from exc

    def save(self, checkpoint: Checkpoint) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"last_successful_record_id": checkpoint.last_successful_record_id}

        temporary_path: Path | None = None

        try:
            with NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                delete=False,
            ) as temporary:
                json.dump(payload, temporary)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)

            last_error: OSError | None = None

            for _ in range(5):
                try:
                    os.replace(temporary_path, self.path)
                    return
                except PermissionError as exc:
                    last_error = exc

            if last_error is not None:
                raise last_error
        finally:
            if temporary_path is not None and temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

    def reset(self) -> Checkpoint:
        if self.path.exists():
            self._quarantine_corrupt_file()
        empty = Checkpoint()
        self.save(empty)
        return empty

    def _quarantine_corrupt_file(self) -> None:
        quarantine_path = self.path.with_suffix(self.path.suffix + ".invalid")
        try:
            os.replace(self.path, quarantine_path)
        except OSError as exc:
            raise CheckpointCorruptError(
                f"checkpoint is invalid and could not be quarantined: {self.path}"
            ) from exc
