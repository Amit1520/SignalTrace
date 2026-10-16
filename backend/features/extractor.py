from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable

import sqlite3

from backend.database.repository import SQLiteRepository

from .models import ApplicationFeatureSet, FeatureBundle, FeatureQuality
from .normalization import (
    command_category,
    destination_scope,
    file_directory,
    file_extension,
    normalize_command_line,
    normalize_destination,
    normalize_executable_path,
    normalize_file_path,
)


class FeatureExtractor:
    def __init__(self, repository: SQLiteRepository) -> None:
        self.repository = repository

    def extract(self) -> FeatureBundle:
        process_rows = self.repository.list_events("process_creation")
        network_rows = self.repository.list_events("network_connection")
        file_rows = self.repository.list_events("file_activity")
        processes_by_guid = {
            row["process_guid"]: row for row in process_rows if row["process_guid"]
        }
        grouped: dict[str, dict[str, list[sqlite3.Row]]] = defaultdict(
            lambda: {"process": [], "network": [], "file": []}
        )
        unassigned = 0
        for kind, rows in (("process", process_rows), ("network", network_rows), ("file", file_rows)):
            for row in rows:
                identity = normalize_executable_path(row["image_path"])
                if identity is None and row["process_guid"]:
                    owner = processes_by_guid.get(row["process_guid"])
                    identity = normalize_executable_path(owner["image_path"]) if owner else None
                if identity is None:
                    unassigned += 1
                    continue
                grouped[identity][kind].append(row)
        profiles = [self._build_profile(identity, rows) for identity, rows in sorted(grouped.items())]
        return FeatureBundle(profiles=profiles, unassigned_observations=unassigned)

    def _build_profile(
        self, identity: str, rows: dict[str, list[sqlite3.Row]]
    ) -> ApplicationFeatureSet:
        all_rows = rows["process"] + rows["network"] + rows["file"]
        timestamps = [_parse_timestamp(row["timestamp"]) for row in all_rows]
        known_timestamps = [value for value in timestamps if value is not None]
        process_launch = Counter()
        child_process = Counter()
        parent_patterns = Counter()
        tree_depth = Counter()
        executable = Counter()
        hashes = Counter()
        command_patterns = Counter()
        command_categories = Counter()
        network_destinations = Counter()
        network_ports = Counter()
        network_protocols = Counter()
        network_scopes = Counter()
        network_first: dict[str, datetime] = {}
        network_last: dict[str, datetime] = {}
        file_directories = Counter()
        file_paths = Counter()
        file_extensions = Counter()
        activity_hours = Counter()
        activity_weekdays = Counter()
        privilege = Counter()
        process_by_guid = {
            row["process_guid"]: row for row in rows["process"] if row["process_guid"]
        }
        for row in rows["process"]:
            image = normalize_executable_path(row["image_path"])
            if image:
                process_launch[image] += 1
                executable[image] += 1
            parent = normalize_executable_path(row["parent_image"])
            if parent:
                parent_patterns[parent] += 1
            if parent == identity and image:
                child_process[image] += 1
            depth = _process_depth(row, process_by_guid)
            if depth is not None:
                tree_depth[str(depth)] += 1
            for digest in _json_hashes(row["hashes_json"]):
                hashes[digest] += 1
            pattern = normalize_command_line(row["command_line"])
            if pattern:
                command_patterns[pattern] += 1
            category = command_category(row["command_line"])
            if category:
                command_categories[category] += 1
            if row["integrity_level"]:
                privilege[row["integrity_level"]] += 1
            elif row["user_name"]:
                privilege[f"user:{row['user_name']}"] += 1
        for row in rows["network"]:
            destination = normalize_destination(row["destination_ip"] or row["destination_hostname"])
            if destination:
                network_destinations[destination] += 1
                timestamp = _parse_timestamp(row["timestamp"])
                if timestamp:
                    network_first[destination] = min(network_first.get(destination, timestamp), timestamp)
                    network_last[destination] = max(network_last.get(destination, timestamp), timestamp)
            if row["destination_port"] is not None:
                network_ports[str(row["destination_port"])] += 1
            if row["protocol"]:
                network_protocols[row["protocol"].lower()] += 1
            scope = destination_scope(row["destination_ip"])
            if scope:
                network_scopes[scope] += 1
        for row in rows["file"]:
            path = normalize_file_path(row["target_filename"])
            directory = file_directory(path)
            extension = file_extension(path)
            if path:
                file_paths[path] += 1
            if directory:
                file_directories[directory] += 1
            if extension:
                file_extensions[extension] += 1
        for timestamp in known_timestamps:
            activity_hours[f"{timestamp.hour:02d}"] += 1
            activity_weekdays[str(timestamp.weekday())] += 1
        return ApplicationFeatureSet(
            application_identity=identity,
            observation_count=len(all_rows),
            first_seen=min(known_timestamps) if known_timestamps else None,
            last_seen=max(known_timestamps) if known_timestamps else None,
            process_launch_frequency=_sorted_counts(process_launch),
            child_process_frequency=_sorted_counts(child_process),
            parent_process_patterns=_sorted_counts(parent_patterns),
            process_tree_depth=_sorted_counts(tree_depth),
            executable_frequency=_sorted_counts(executable),
            hash_frequency=_sorted_counts(hashes),
            network_destination_frequency=_sorted_counts(network_destinations),
            network_destination_ports=_sorted_counts(network_ports),
            network_protocol_frequency=_sorted_counts(network_protocols),
            network_scope_frequency=_sorted_counts(network_scopes),
            network_first_seen=dict(sorted(network_first.items())),
            network_last_seen=dict(sorted(network_last.items())),
            file_directory_frequency=_sorted_counts(file_directories),
            file_path_frequency=_sorted_counts(file_paths),
            file_extension_frequency=_sorted_counts(file_extensions),
            command_pattern_frequency=_sorted_counts(command_patterns),
            command_category_frequency=_sorted_counts(command_categories),
            activity_by_hour=_sorted_counts(activity_hours),
            activity_by_weekday=_sorted_counts(activity_weekdays),
            privilege_frequency=_sorted_counts(privilege),
            privilege_data_available=bool(privilege),
            quality=FeatureQuality(
                observations=len(all_rows),
                complete_timestamps=len(known_timestamps),
                missing_timestamp_count=len(all_rows) - len(known_timestamps),
                missing_application_identity_count=0,
            ),
        )


def _sorted_counts(values: Counter[str]) -> dict[str, int]:
    return {key: values[key] for key in sorted(values)}


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _json_hashes(value: str | None) -> Iterable[str]:
    if not value:
        return ()
    try:
        import json

        payload = json.loads(value)
    except (TypeError, ValueError):
        return ()
    return (f"{key}={payload[key]}" for key in sorted(payload) if payload[key])


def _process_depth(row: sqlite3.Row, process_by_guid: dict[str, sqlite3.Row]) -> int | None:
    if not row["process_guid"]:
        return None
    depth = 1
    parent_guid = row["parent_process_guid"]
    visited = {row["process_guid"]}
    while parent_guid and parent_guid in process_by_guid and parent_guid not in visited:
        visited.add(parent_guid)
        depth += 1
        parent_guid = process_by_guid[parent_guid]["parent_process_guid"]
    return depth
