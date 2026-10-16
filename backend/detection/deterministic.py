from backend.features.models import SignalTraceProfile

from .models import Signal, SignalCategory


def compare_observation(observation, profile: SignalTraceProfile) -> list[Signal]:
    attrs = observation.observed_features
    signals: list[Signal] = []
    if attrs.get("kind") == "process_creation":
        _add_missing(signals, SignalCategory.PROCESS, "new_executable_path", attrs.get("executable"), profile.process_dna.get("executable_frequency", {}))
        _add_missing(signals, SignalCategory.PROCESS, "new_child_process", attrs.get("child_process"), profile.process_dna.get("child_process_frequency", {}))
        _add_missing(signals, SignalCategory.PROCESS, "new_parent_child_relationship", attrs.get("parent"), profile.process_dna.get("parent_process_patterns", {}))
        _add_missing(signals, SignalCategory.PROCESS, "unusual_hash", attrs.get("hash"), profile.process_dna.get("hash_frequency", {}))
        _add_missing(signals, SignalCategory.EXECUTION, "new_command_pattern", attrs.get("command_pattern"), profile.execution_dna.get("command_pattern_frequency", {}))
        _add_missing(signals, SignalCategory.EXECUTION, "new_execution_category", attrs.get("category"), profile.execution_dna.get("command_category_frequency", {}))
        _add_frequency_signal(signals, SignalCategory.PROCESS, attrs, profile.process_dna.get("launch_frequency", {}), "unusual_process_frequency")
    elif attrs.get("kind") == "network_connection":
        _add_missing(signals, SignalCategory.NETWORK, "new_destination", attrs.get("destination"), profile.network_dna.get("destination_frequency", {}))
        _add_missing(signals, SignalCategory.NETWORK, "unusual_port", _string(attrs.get("port")), profile.network_dna.get("destination_ports", {}))
        _add_missing(signals, SignalCategory.NETWORK, "unusual_protocol", attrs.get("protocol"), profile.network_dna.get("protocol_frequency", {}))
        if attrs.get("scope") == "external" and profile.network_dna.get("scope_frequency", {}).get("external", 0) == 0:
            signals.append(_signal(SignalCategory.NETWORK, "new_external_connection", attrs.get("destination"), "external destination was not observed", 0.8))
        _add_frequency_signal(signals, SignalCategory.NETWORK, attrs, profile.network_dna.get("destination_frequency", {}), "unusual_destination_frequency")
    elif attrs.get("kind") == "file_activity":
        _add_missing(signals, SignalCategory.FILE, "new_directory", attrs.get("directory"), profile.file_dna.get("directory_frequency", {}))
        _add_missing(signals, SignalCategory.FILE, "new_file_path", attrs.get("path"), profile.file_dna.get("path_frequency", {}))
        _add_missing(signals, SignalCategory.FILE, "new_extension", attrs.get("extension"), profile.file_dna.get("extension_frequency", {}))
        _add_frequency_signal(signals, SignalCategory.FILE, attrs, profile.file_dna.get("path_frequency", {}), "unusual_file_activity")
    if attrs.get("integrity_level") and profile.privilege_dna.get("available") and attrs["integrity_level"] not in profile.privilege_dna.get("frequency", {}):
        signals.append(_signal(SignalCategory.PRIVILEGE, "unexpected_integrity_change", attrs["integrity_level"], "integrity level was not observed in the baseline", 0.7))
    if attrs.get("hour") is not None and str(attrs["hour"]).zfill(2) not in profile.temporal_dna.get("activity_by_hour", {}):
        signals.append(_signal(SignalCategory.TEMPORAL, "outside_normal_hour", attrs["hour"], "hour was not observed in the baseline", 0.5))
    if attrs.get("weekday") is not None and str(attrs["weekday"]) not in profile.temporal_dna.get("activity_by_weekday", {}):
        signals.append(_signal(SignalCategory.TEMPORAL, "outside_normal_weekday", attrs["weekday"], "weekday was not observed in the baseline", 0.4))
    return signals


def _add_missing(signals, category, signal_type, observed, baseline) -> None:
    if observed is not None and observed not in baseline:
        signals.append(_signal(category, signal_type, observed, "value was not observed in the baseline", 0.5))


def _add_frequency_signal(signals, category, attrs, baseline, signal_type) -> None:
    observed = attrs.get("destination") or attrs.get("path") or attrs.get("executable")
    observed_frequency = attrs.get("frequency")
    if observed is not None and observed_frequency is not None and observed in baseline and observed_frequency > baseline[observed]:
        signals.append(_signal(category, signal_type, observed_frequency, "observed frequency exceeded the baseline", 0.35))


def _signal(category, signal_type, observed, reason, weight) -> Signal:
    return Signal(category=category, signal_type=signal_type, observed_value=observed, baseline_value=None, deviation=reason, weight=weight, contribution=weight)


def _string(value: object) -> str | None:
    return str(value) if value is not None else None
