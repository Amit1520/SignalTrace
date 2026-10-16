from datetime import datetime, timezone

from backend.baseline.builder import BaselineBuilder, BaselineSettings
from backend.database.repository import SQLiteRepository
from backend.features.extractor import FeatureExtractor
from backend.features.normalization import (
    command_category,
    destination_scope,
    file_directory,
    file_extension,
    normalize_command_line,
    normalize_executable_path,
)
from backend.tests.test_database import file_event, network_event, process_event


def test_safe_normalization_is_deterministic() -> None:
    assert normalize_executable_path(r"C:\Windows\\System32\APP.EXE") == "c:/windows/system32/app.exe"
    assert normalize_command_line(r"APP.EXE C:\Temp\File.txt 192.0.2.1 42") == "app.exe <path> <ip> <number>"
    assert command_category(r"C:\Tools\APP.EXE --mode") == "app.exe"
    assert file_directory(r"C:\Temp\File.TXT") == "c:/temp"
    assert file_extension(r"C:\Temp\File.TXT") == ".txt"
    assert destination_scope("192.168.1.2") == "local"
    assert destination_scope("8.8.8.8") == "external"


def test_feature_extraction_covers_dna_categories(tmp_path) -> None:
    path = tmp_path / "signaltrace.sqlite3"
    with SQLiteRepository(path) as repository:
        repository.insert_events([process_event(), file_event(), network_event()])
        bundle = FeatureExtractor(repository).extract()

    assert len(bundle.profiles) == 1
    profile = bundle.profiles[0]
    assert profile.application_identity.endswith("cmd.exe")
    assert profile.observation_count == 3
    assert profile.process_launch_frequency
    assert profile.network_destination_frequency == {"203.0.113.10": 1}
    assert profile.network_destination_ports == {"443": 1}
    assert profile.file_directory_frequency == {"c:/temp": 1}
    assert profile.file_extension_frequency == {".txt": 1}
    assert profile.command_category_frequency == {"cmd.exe": 1}
    assert profile.activity_by_hour == {"10": 3}
    assert profile.privilege_data_available is True


def test_sparse_profile_is_explicitly_insufficient(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        repository.insert_events([process_event()])
        profile = BaselineBuilder(repository, BaselineSettings(minimum_observations=2)).build(
            "c:/windows/system32/cmd.exe"
        )

    assert profile is not None
    assert profile.profile_status == "insufficient_data"
    assert profile.observation_count == 1


def test_profile_persistence_reload_and_rebuild_versions(tmp_path) -> None:
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        repository.insert_events([process_event()])
        builder = BaselineBuilder(repository, BaselineSettings(minimum_observations=1))
        first = builder.build("c:/windows/system32/cmd.exe")
        second = builder.rebuild("c:/windows/system32/cmd.exe")
        loaded = builder.load("c:/windows/system32/cmd.exe")

    assert first is not None and second is not None and loaded is not None
    assert first.profile_version == 1
    assert second.profile_version == 2
    assert loaded.profile_version == 2
    assert loaded.process_dna == first.process_dna


def test_identical_input_produces_identical_features(tmp_path) -> None:
    path_a = tmp_path / "a.sqlite3"
    path_b = tmp_path / "b.sqlite3"
    with SQLiteRepository(path_a) as repository_a, SQLiteRepository(path_b) as repository_b:
        events = [process_event(), network_event(), file_event()]
        repository_a.insert_events(events)
        repository_b.insert_events(events)
        first = FeatureExtractor(repository_a).extract()
        second = FeatureExtractor(repository_b).extract()

    assert first == second


def test_missing_identity_is_not_fabricated(tmp_path) -> None:
    event = process_event("missing-image")
    event.image = None
    with SQLiteRepository(tmp_path / "signaltrace.sqlite3") as repository:
        repository.insert_events([event])
        bundle = FeatureExtractor(repository).extract()

    assert bundle.profiles == []
    assert bundle.unassigned_observations == 1
