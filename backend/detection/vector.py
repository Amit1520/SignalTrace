from backend.features.normalization import (
    destination_scope,
    file_directory,
    file_extension,
    normalize_command_line,
    normalize_destination,
    normalize_executable_path,
    normalize_file_path,
)

from .models import BehaviorObservation, FEATURE_SCHEMA_VERSION

VECTOR_FEATURE_NAMES = (
    "event_process",
    "event_network",
    "event_file",
    "has_parent",
    "parent_frequency",
    "known_destination",
    "known_port",
    "known_protocol",
    "has_external_destination",
    "known_file_directory",
    "known_file_extension",
    "known_command_pattern",
    "known_execution_category",
    "hour_of_day",
    "day_of_week",
    "privilege_available",
)


def observation_from_row(
    kind: str,
    row: object,
    profile: object | None = None,
) -> BehaviorObservation:
    columns = set(row.keys())
    get = lambda name: row[name] if name in columns else None

    image = normalize_executable_path(get("image_path"))
    application = image or ""

    attributes: dict[str, str | int | float | bool | None] = {
        "kind": kind,
        "host": get("host"),
        "process_guid": get("process_guid"),
        "parent_process_guid": get("parent_process_guid"),
        "process_id": get("process_id"),
        "image_path": image,
    }

    vector = {name: 0.0 for name in VECTOR_FEATURE_NAMES}
    vector[f"event_{_event_suffix(kind)}"] = 1.0

    timestamp = _parse_timestamp(get("timestamp"))

    parent = normalize_executable_path(get("parent_image"))

    if get("parent_process_guid") or parent:
        vector["has_parent"] = 1.0

    if kind == "network_connection":
        destination = normalize_destination(
            get("destination_ip") or get("destination_hostname")
        )
        scope = destination_scope(get("destination_ip"))

        attributes.update(
            {
                "destination": destination,
                "port": get("destination_port"),
                "protocol": (get("protocol") or "").lower() or None,
                "scope": scope,
            }
        )

        vector["has_external_destination"] = float(scope == "external")
        vector["known_destination"] = float(
            _profile_has(
                profile,
                "network_dna",
                "destination_frequency",
                destination,
            )
        )
        vector["known_port"] = float(
            _profile_has(
                profile,
                "network_dna",
                "destination_ports",
                _string(get("destination_port")),
            )
        )
        vector["known_protocol"] = float(
            _profile_has(
                profile,
                "network_dna",
                "protocol_frequency",
                attributes["protocol"],
            )
        )

    elif kind == "file_activity":
        path = normalize_file_path(get("target_filename"))
        directory = file_directory(path)
        extension = file_extension(path)

        attributes.update(
            {
                "path": path,
                "directory": directory,
                "extension": extension,
            }
        )

        vector["known_file_directory"] = float(
            _profile_has(
                profile,
                "file_dna",
                "directory_frequency",
                directory,
            )
        )
        vector["known_file_extension"] = float(
            _profile_has(
                profile,
                "file_dna",
                "extension_frequency",
                extension,
            )
        )

    else:
        command = normalize_command_line(get("command_line"))
        category = _command_category(get("command_line"))
        digest = _first_hash(get("hashes_json"))

        attributes.update(
            {
                "executable": image,
                "parent": parent,
                "command_pattern": command,
                "category": category,
                "hash": digest,
            }
        )

        attributes["child_process"] = image if parent else None
        attributes["integrity_level"] = get("integrity_level")

        # Preserve parent-process behavioral variation for the ML model.
        vector["parent_frequency"] = _profile_frequency_ratio(
            profile,
            "process_dna",
            "parent_process_patterns",
            parent,
        )

        vector["known_command_pattern"] = float(
            _profile_has(
                profile,
                "execution_dna",
                "command_pattern_frequency",
                command,
            )
        )

        vector["known_execution_category"] = float(
            _profile_has(
                profile,
                "execution_dna",
                "command_category_frequency",
                category,
            )
        )

        if get("integrity_level") or get("user_name"):
            vector["privilege_available"] = 1.0

    if timestamp:
        vector["hour_of_day"] = timestamp.hour / 23.0
        vector["day_of_week"] = timestamp.weekday() / 6.0

        attributes.update(
            {
                "hour": timestamp.hour,
                "weekday": timestamp.weekday(),
            }
        )

    return BehaviorObservation(
        application_identity=application,
        timestamp=timestamp,
        feature_vector={
            name: vector[name]
            for name in VECTOR_FEATURE_NAMES
        },
        observed_features=attributes,
        provenance_references=[
            str(get("record_id"))
        ]
        if get("record_id")
        else [],
    )


def validate_vector_schema(
    observation: BehaviorObservation,
) -> bool:
    return (
        observation.feature_schema_version == FEATURE_SCHEMA_VERSION
        and tuple(observation.feature_vector) == VECTOR_FEATURE_NAMES
    )


def _event_suffix(kind: str) -> str:
    return {
        "process_creation": "process",
        "network_connection": "network",
        "file_activity": "file",
    }.get(kind, "process")


def _profile_has(
    profile: object | None,
    category: str,
    key: str,
    value: object,
) -> bool:
    if profile is None or value is None:
        return False

    section = getattr(profile, category, {})

    values = (
        section.get(key, {})
        if isinstance(section, dict)
        else {}
    )

    return value in values


def _profile_frequency_ratio(
    profile: object | None,
    category: str,
    key: str,
    value: object,
) -> float:
    """
    Return the observed value's share of the baseline frequency.

    Example:
        reg.exe = 16 / 27 -> 0.5926
        python.exe = 6 / 27 -> 0.2222

    Unknown values return 0.0.

    This preserves behavioral variation for statistical detection
    without encoding executable paths as arbitrary categorical numbers.
    """
    if profile is None or value is None:
        return 0.0

    section = getattr(profile, category, {})

    frequencies = (
        section.get(key, {})
        if isinstance(section, dict)
        else {}
    )

    if not isinstance(frequencies, dict):
        return 0.0

    frequency = frequencies.get(value)

    if not isinstance(frequency, (int, float)) or frequency <= 0:
        return 0.0

    total = sum(
        float(item)
        for item in frequencies.values()
        if isinstance(item, (int, float)) and item > 0
    )

    if total <= 0:
        return 0.0

    return min(1.0, float(frequency) / total)


def _parse_timestamp(value):
    from datetime import datetime

    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _string(value: object) -> str | None:
    return str(value) if value is not None else None


def _first_hash(value: str | None) -> str | None:
    import json

    try:
        hashes = json.loads(value or "{}")
    except (TypeError, ValueError):
        return None

    return next(
        (
            f"{key}={hashes[key]}"
            for key in sorted(hashes)
        ),
        None,
    )


def _command_category(value: str | None) -> str | None:
    if not value:
        return None

    return normalize_executable_path(
        value.split(None, 1)[0]
    ).rsplit("/", 1)[-1]