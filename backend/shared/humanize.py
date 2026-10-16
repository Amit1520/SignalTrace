"""Plain-language humanization helpers shared by the detection/correlation
layer and the AI explanation layer.

This module has NO imports from backend.ai or backend.incidents, by design,
so it can be safely imported from both without any risk of a circular
import: backend/incidents/correlator.py uses it to write a specific,
human-readable IncidentEvent.description at correlation time (in memory,
before anything touches a database); backend/ai/evidence.py uses the same
functions when building explanation evidence from persisted signals.

Both callers may pass either a native Python value (as held in-memory on a
Signal, e.g. a plain string or int) or a JSON-encoded string (as read back
from a database TEXT column) -- every function here accepts both without
the caller needing to know which it has.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

# Plain-language phrase for each known signal type. Anything not listed
# falls back to a readable version of its name (underscores -> spaces).
FRIENDLY_SIGNAL_PHRASES = {
    "new_child_process": "started a program it had not started before",
    "new_parent_child_relationship": "was launched by a different program than usual",
    "process_drift": "ran in a way that does not match its usual pattern",
    "network_drift": "connected to the network in a way that does not match its usual pattern",
    "new_execution_category": "ran in a new way that had not been observed before",
    "outside_normal_hour": "was active at a time of day it does not usually run",
    "outside_normal_weekday": "was active on a day of the week it does not usually run",
}

# Plain-language label for each signal category, for short reader-facing use.
FRIENDLY_CATEGORY_LABELS = {
    "execution": "Program activity",
    "process": "Program behavior",
    "temporal": "Timing",
    "network": "Network activity",
    "file": "File activity",
    "privilege": "Permission level",
}

TEMPORAL_SIGNAL_TYPES = {"outside_normal_hour", "outside_normal_weekday"}


def friendly_signal_phrase(signal_type: str) -> str:
    if signal_type in FRIENDLY_SIGNAL_PHRASES:
        return FRIENDLY_SIGNAL_PHRASES[signal_type]
    return "behaved in a way not seen before: " + signal_type.replace("_", " ")


def friendly_category_label(category: str) -> str:
    return FRIENDLY_CATEGORY_LABELS.get(category, category.replace("_", " ").capitalize())


def basename(value: str | None) -> str | None:
    """Plain file name from a full path, used to detect self-referencing signals."""

    if not value:
        return None
    name = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return name or None


def extract_program_name(raw_value: Any) -> str | None:
    """
    Best-effort: pull a short program file name out of a signal's observed
    value. Accepts a plain in-memory string, a JSON-encoded string (e.g.
    ``'"c:/windows/system32/conhost.exe"'`` as read from a database TEXT
    column), or any other value. Returns None for anything that doesn't
    look like a usable name, rather than showing raw JSON or a long path
    to the reader.
    """

    if raw_value is None:
        return None

    text = raw_value
    if isinstance(raw_value, str):
        try:
            decoded = json.loads(raw_value)
            if isinstance(decoded, str):
                text = decoded
        except Exception:
            text = raw_value.strip().strip('"')

    text = str(text).strip()
    if not text or len(text) > 200:
        return None

    name = text.replace("\\", "/").rsplit("/", 1)[-1]
    # Reject values that clearly aren't a short program name (command
    # lines, GUIDs, timestamps, etc.) -- better to fall back to the generic
    # phrase than to show something unreadable.
    if not name or len(name) > 60 or " " in name or "=" in name:
        return None
    return name


def distinct_program_names(observed_values: list[Any], limit: int = 2) -> list[str]:
    """Real program names found across a list of observed values, deduped, in order."""

    names: list[str] = []
    seen: set[str] = set()
    for value in observed_values:
        name = extract_program_name(value)
        if name and name.casefold() not in seen:
            seen.add(name.casefold())
            names.append(name)
        if len(names) >= limit:
            break
    return names


def join_names(names: list[str]) -> str:
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return " and ".join(names)


def hour_to_phrase(hour: int) -> str | None:
    if not (0 <= hour <= 23):
        return None
    period = "AM" if hour < 12 else "PM"
    display = hour % 12 or 12
    return f"around {display} {period}"


def format_hour(raw_value: Any) -> str | None:
    """0-23 hour value (native int or JSON-encoded) -> 'around 3 PM'-style phrase."""

    try:
        value = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
        hour = int(value)
    except Exception:
        return None
    return hour_to_phrase(hour)


def format_hour_from_timestamp(raw_timestamp: Any) -> str | None:
    """
    Convert a stored timestamp to a local-time "around 3 PM" phrase.

    Timestamps are stored in UTC (e.g. "2026-10-01T06:19:15Z"), but the
    frontend displays times via JavaScript's toLocaleTimeString(), which
    converts to the viewer's local timezone automatically. Taking .hour
    directly off a UTC-aware datetime returns the UTC hour, not the local
    one -- for a UTC+5:30 timezone that is a ~5.5 hour mismatch (e.g. "11
    AM" here when the UI, correctly, shows "5 PM" for the same moment).
    .astimezone() with no argument converts to the system's local timezone
    before the hour is read, matching what the UI shows elsewhere.
    """

    if not raw_timestamp:
        return None
    try:
        if isinstance(raw_timestamp, datetime):
            moment = raw_timestamp
        else:
            text = str(raw_timestamp).replace("Z", "+00:00")
            moment = datetime.fromisoformat(text)

        # A naive datetime (no tzinfo) is treated as UTC, matching the
        # convention backend/incidents/correlator.py's own _utc() helper
        # already uses for exactly this reason: "Existing persisted
        # incidents may contain naive timestamps... treat legacy naive
        # timestamps as UTC." Without this, an in-memory naive-UTC
        # detection.timestamp (as opposed to a JSON string read back from
        # the database, which always carries an explicit "Z"/"+00:00" and
        # so always has tzinfo) would skip local conversion entirely and
        # silently reproduce the UTC-vs-local mismatch this function exists
        # to fix.
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone()
        hour = moment.hour
        return hour_to_phrase(hour)
    except Exception:
        return None


def specific_observation(
    signal_type: str,
    names: list[str],
    times: str,
    app_basename: str | None = None,
) -> str:
    """
    A concrete, plain-language sentence naming the real program involved,
    when the underlying signal value gives us one. Falls back to the
    generic phrase (see friendly_signal_phrase) when no usable name is
    available.

    When the named program is the application itself (a process legitimately
    starting another copy of its own executable -- common for things like
    git.exe spawning git.exe subcommands), this is phrased as "another copy
    of itself" rather than repeating the same name twice, which otherwise
    reads like a mistake ("git.exe started git.exe") to a non-technical
    reader even though it is accurate.
    """

    self_reference = bool(
        app_basename
        and len(names) == 1
        and names[0].casefold() == app_basename.casefold()
    )
    shown = "another copy of itself" if self_reference else join_names(names)

    if signal_type == "new_child_process":
        if self_reference:
            return f"This application started another copy of itself ({times} recently)."
        if shown:
            return f"This application started {shown}, a program it had not run before ({times} recently)."
        return f"This application started a new program it had not run before ({times} recently)."

    if signal_type == "new_parent_child_relationship":
        if self_reference:
            return f"This application was started by another copy of itself ({times} recently)."
        if shown:
            return (
                f"This application was started by {shown}, which does not usually "
                f"start it ({times} recently)."
            )
        return f"This application was launched by a different program than usual ({times} recently)."

    phrase = friendly_signal_phrase(signal_type)
    return f"This application {phrase} ({times} recently)."


def format_span(timestamps: list) -> str | None:
    """
    A short, plain-language description of how far apart a group's
    occurrences were, e.g. "all within 3 minutes" or "over about 2 hours".

    Accepts a list of raw timestamps (native datetime, ISO string, or any
    mix); entries that can't be parsed are skipped. Returns None when there
    are fewer than two usable timestamps, or when the span is too short to
    be a meaningful detail (under about 10 seconds -- essentially the same
    instant).
    """

    moments = []
    for raw in timestamps:
        if not raw:
            continue
        try:
            if isinstance(raw, datetime):
                moment = raw
            else:
                moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            moments.append(moment)
        except Exception:
            continue

    if len(moments) < 2:
        return None

    span_seconds = (max(moments) - min(moments)).total_seconds()
    if span_seconds < 10:
        return None

    if span_seconds < 60:
        return f"all within {int(span_seconds)} seconds"
    if span_seconds < 3600:
        minutes = max(1, round(span_seconds / 60))
        return f"all within {minutes} minute{'s' if minutes != 1 else ''}"
    if span_seconds < 86400:
        hours = max(1, round(span_seconds / 3600))
        return f"over about {hours} hour{'s' if hours != 1 else ''}"
    days = max(1, round(span_seconds / 86400))
    return f"over about {days} day{'s' if days != 1 else ''}"


def temporal_observation(time_phrase: str | None) -> str:
    if time_phrase:
        return f"This application was active {time_phrase}, a time it does not usually run."
    return "This application was active at a time it does not usually run."


TEMPORAL_DEVIATION_NOTE = (
    "Unusual timing alone is weak evidence on its own; it is context, "
    "not a specific behavior."
)