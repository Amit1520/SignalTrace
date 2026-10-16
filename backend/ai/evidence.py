"""Builds the structured evidence given to explanations, in plain language.

This version pulls the real detection signals (observed values, deviations,
occurrence counts) for an incident directly from the database, instead of
relying on the generic per-event "reason" text written by detection/engine.py
(e.g. "behavioral deviation evidence"). If the database lookup fails for any
reason, it falls back to the old per-event description so the explanation
pipeline never breaks -- the fallback is just less detailed.

Wording is deliberately non-technical: this text is read by security
analysts as well as people with no security background, so signal types and
categories are translated into plain phrases (see backend.shared.humanize)
rather than shown as raw identifiers. The same humanize module is used by
backend/incidents/correlator.py, so the incident Chronology/Evidence panels
and this AI explanation produce identical wording from one source.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from backend.incidents.models import Incident

from backend.shared import humanize

from .models import EvidenceItem, ExplanationEvidence

MAX_SIGNAL_GROUPS = 8
MAX_EXAMPLES_PER_GROUP = 3
MAX_SUPPORTING_REFERENCES = 5
MAX_VALUE_CHARS = 140

# Signals that only describe unusual timing are weak context on their own,
# not a specific behavior, so they are merged into a single plain item.
_TEMPORAL_TYPES = {"outside_normal_hour", "outside_normal_weekday"}



def build_explanation_evidence(incident: Incident) -> ExplanationEvidence:
    """
    Build plain-language, structured evidence for an incident explanation.

    Tries to load the real underlying signals for this incident's detections
    from the database; falls back to the incident's own timeline description
    if that is unavailable.
    """

    signals_by_detection = _load_signals_by_detection(incident)
    app_basename = humanize.basename(incident.application_identity)

    if signals_by_detection:
        signals = _signals_from_detections(signals_by_detection, app_basename)
    else:
        signals = _signals_from_timeline(incident)

    process_chain = [
        {
            "process_guid": node.process_guid,
            "parent_guid": node.parent_guid,
            "process_id": node.process_id,
            "image_path": _redact_path(node.image_path),
        }
        for node in incident.process_chain
    ]
    timeline = [
        {
            "reference": event.event_reference,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "category": event.event_category,
            "process_guid": event.process_guid,
            "description": event.description[:500],
        }
        for event in incident.timeline
    ]

    return ExplanationEvidence(
        incident_id=incident.incident_id,
        application_identity=_redact_path(incident.application_identity)
        or "unknown application",
        severity=incident.severity.value,
        deviation_score=max(
            (event.contribution for event in incident.timeline), default=0.0
        ),
        confidence=incident.confidence,
        signals=signals,
        process_chain=process_chain,
        timeline=timeline,
        provenance_references=sorted(set(incident.contributing_evidence)),
        known_limitations=[
            "This explanation is based only on the activity evidence supplied.",
            "This is a statistical deviation, not a determination that anything is malware.",
            "Some process or network context may be missing if telemetry was incomplete.",
        ],
    )


# ---------------------------------------------------------------------------
# Database lookup (best-effort, never fatal)
# ---------------------------------------------------------------------------

def _load_signals_by_detection(
    incident: Incident,
) -> dict[str, list[dict[str, Any]]]:
    """
    Return {detection_id: [signal, ...]} for this incident's detections.

    Returns an empty dict on any failure (missing tables/columns, no
    database configured, etc.) so the caller can fall back safely.
    """

    detection_ids = list(
        dict.fromkeys(
            [event.event_reference for event in incident.timeline]
            + list(incident.contributing_evidence)
        )
    )
    if not detection_ids:
        return {}

    try:
        import sqlite3

        try:
            from backend.database.config import DatabaseSettings

            db_path = Path(DatabaseSettings().path)
        except Exception:
            db_path = Path("data/signaltrace.sqlite3")

        if not db_path.is_file():
            return {}

        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            placeholders = ",".join("?" for _ in detection_ids)
            rows = connection.execute(
                f"""
                SELECT
                    a.detection_id AS detection_id,
                    a.timestamp AS timestamp,
                    s.category AS category,
                    s.signal_type AS signal_type,
                    s.observed_value_json AS observed_value_json,
                    s.baseline_value_json AS baseline_value_json,
                    s.deviation AS deviation,
                    s.contribution AS contribution
                FROM detection_signals s
                JOIN anomalies a ON a.id = s.anomaly_id
                WHERE a.detection_id IN ({placeholders})
                """,
                detection_ids,
            ).fetchall()
        finally:
            connection.close()

    except Exception:
        return {}

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["detection_id"]].append(
            {
                "category": row["category"],
                "signal_type": row["signal_type"],
                "observed_value": row["observed_value_json"],
                "baseline_value": row["baseline_value_json"],
                "deviation": row["deviation"],
                "contribution": row["contribution"] or 0.0,
                "timestamp": row["timestamp"],
            }
        )
    return dict(grouped)


# ---------------------------------------------------------------------------
# Signal aggregation
# ---------------------------------------------------------------------------

def _signals_from_detections(
    signals_by_detection: Mapping[str, list[dict[str, Any]]],
    app_basename: str | None = None,
) -> list[EvidenceItem]:
    groups: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for detection_id, rows in signals_by_detection.items():
        for signal in rows:
            key = (str(signal.get("category") or ""), str(signal.get("signal_type") or ""))
            groups[key].append((detection_id, signal))

    # (strength, EvidenceItem) pairs. EvidenceItem itself only carries
    # reference/category/observation/deviation (no signal_type field), so
    # the sort strength is computed here, alongside the group it came from,
    # rather than read back off the constructed item afterward.
    behavioral: list[tuple[float, EvidenceItem]] = []
    temporal_members: list[tuple[str, dict[str, Any]]] = []

    for (category, signal_type), members in groups.items():
        if signal_type in _TEMPORAL_TYPES:
            temporal_members.extend(members)
            continue
        strength = sum(float(signal.get("contribution") or 0.0) for _, signal in members)
        behavioral.append((strength, _group_item(category, signal_type, members, app_basename)))

    behavioral.sort(key=lambda pair: -pair[0])
    items = [item for _, item in behavioral[: MAX_SIGNAL_GROUPS - 1]]

    temporal_item = _temporal_item(temporal_members)
    if temporal_item is not None:
        items.append(temporal_item)
    return items[:MAX_SIGNAL_GROUPS] or _placeholder_items()


def _group_item(
    category: str,
    signal_type: str,
    members: list[tuple[str, dict[str, Any]]],
    app_basename: str | None = None,
) -> EvidenceItem:
    detections = list(dict.fromkeys(detection_id for detection_id, _ in members))
    count = len(members)
    times = "once" if count == 1 else f"{count} times"

    names = humanize.distinct_program_names([signal.get("observed_value") for _, signal in members])
    observation = humanize.specific_observation(signal_type, names, times, app_basename)

    # A real elapsed-time detail (e.g. "all within 3 minutes") when there is
    # more than one occurrence -- this is free, already-available data
    # (timestamps are already loaded per signal) that gives the reader a
    # sense of whether this was one quick burst or spread-out activity,
    # without needing a new database query or model involvement.
    if count > 1:
        span = humanize.format_span([signal.get("timestamp") for _, signal in members])
        if span:
            observation = observation.rstrip(".") + f", {span}."

    deviation = "This does not match what this application normally does."

    return EvidenceItem(
        reference=detections[0],
        category=category or "activity",
        observation=observation,
        deviation=deviation,
    )


def _temporal_item(members: list[tuple[str, dict[str, Any]]]) -> EvidenceItem | None:
    if not members:
        return None
    detections = list(dict.fromkeys(detection_id for detection_id, _ in members))

    # Prefer the properly-localized timestamp over the raw stored hour
    # integer: the timestamp is a verifiable UTC instant we can correctly
    # convert to local time (see humanize.format_hour_from_timestamp), while
    # the hour integer recorded on the signal may itself have been computed
    # in UTC by the detection engine -- the same mismatch that caused
    # "around 11 AM" to be shown for events the rest of the UI displays as
    # "5:17 PM" local. The raw integer is only used when no timestamp is
    # available at all.
    time_phrase = None
    for _, signal in members:
        time_phrase = humanize.format_hour_from_timestamp(signal.get("timestamp"))
        if time_phrase:
            break
    if time_phrase is None:
        for _, signal in members:
            if signal.get("signal_type") == "outside_normal_hour":
                time_phrase = humanize.format_hour(signal.get("observed_value"))
                if time_phrase:
                    break

    return EvidenceItem(
        reference=detections[0],
        category="temporal",
        observation=humanize.temporal_observation(time_phrase),
        deviation=humanize.TEMPORAL_DEVIATION_NOTE,
    )


def _placeholder_items() -> list[EvidenceItem]:
    return [
        EvidenceItem(
            reference="unknown",
            category="activity",
            observation="This application behaved in a way that differs from its usual pattern.",
            deviation="No further detail is available for this event.",
        )
    ]


def _signals_from_timeline(incident: Incident) -> list[EvidenceItem]:
    """Fallback when the database lookup did not return anything usable."""

    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for event in incident.timeline:
        text = event.description.strip() or "This application behaved unusually."
        if text.casefold() in seen:
            continue
        seen.add(text.casefold())
        items.append(
            EvidenceItem(
                reference=event.event_reference,
                category=event.event_category or "activity",
                observation=text[:300],
                deviation=text[:300],
            )
        )
        if len(items) >= MAX_SIGNAL_GROUPS:
            break
    return items or _placeholder_items()


def friendly_category_label(category: str) -> str:
    """Used by genai_provider.py to build the plain-language evidence list."""

    return humanize.friendly_category_label(category)


def _redact_path(value: str | None) -> str | None:
    if not value:
        return value
    parts = value.replace("\\", "/").split("/")
    if len(parts) <= 2:
        return value
    return ".../" + "/".join(parts[-2:])