import ipaddress
import re
from pathlib import PurePosixPath


def normalize_executable_path(value: str | None) -> str | None:
    return _normalize_path(value)


def normalize_file_path(value: str | None) -> str | None:
    return _normalize_path(value)


def normalize_command_line(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    normalized = value.strip().lower().replace("\\", "/")
    normalized = re.sub(r"(?i)([a-z]:/)?(?:[^\s/]+/)+[^\s/]+", "<path>", normalized)
    normalized = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", normalized)
    normalized = re.sub(r"\b\d+\b", "<number>", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def command_category(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    executable = normalize_executable_path(value.strip().split(None, 1)[0])
    return executable.rsplit("/", 1)[-1] if executable else None


def normalize_destination(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    return value.strip().lower().rstrip(".")


def destination_scope(value: str | None) -> str | None:
    destination = normalize_destination(value)
    if not destination:
        return None
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return "unknown"
    if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
        return "local"
    return "external"


def file_extension(value: str | None) -> str | None:
    normalized = normalize_file_path(value)
    if not normalized:
        return None
    suffix = PurePosixPath(normalized).suffix.lower()
    return suffix or "[no_extension]"


def file_directory(value: str | None) -> str | None:
    normalized = normalize_file_path(value)
    if not normalized:
        return None
    directory = str(PurePosixPath(normalized).parent)
    return None if directory == "." else directory


def _normalize_path(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    normalized = value.strip().replace("\\", "/").lower()
    normalized = re.sub(r"/+", "/", normalized)
    if normalized.startswith("//?/"):
        normalized = normalized[3:]
    return normalized.rstrip("/") or "/"
