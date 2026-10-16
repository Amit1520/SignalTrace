import hashlib
import math
from datetime import datetime, timedelta, timezone

from backend.detection.models import DetectionResult, Severity
from backend.shared import humanize

from .models import Incident, IncidentEvent, IncidentStatus, ProcessNode


class CorrelationConfig:
    def __init__(
        self,
        correlation_window: timedelta = timedelta(minutes=10),
        minimum_anomalies: int = 2,
        minimum_categories: int = 2,
        max_incident_span: timedelta = timedelta(minutes=60),
    ) -> None:
        self.correlation_window = correlation_window
        self.minimum_anomalies = minimum_anomalies
        self.minimum_categories = minimum_categories
        # Hard ceiling on total incident duration.  Even if each consecutive
        # detection falls within correlation_window of the previous one, the
        # incident will not absorb any new detection that would push its span
        # (latest_ts - first_seen) beyond this limit.  This prevents an
        # effectively unbounded rolling window caused by long detection chains.
        self.max_incident_span = max_incident_span


class IncidentCorrelator:
    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()

    def correlate(
        self,
        detections: list[DetectionResult],
        existing: list[Incident] | None = None,
    ) -> list[Incident]:
        ordered = sorted(detections, key=_detection_sort_key)
        incidents = [
            item.model_copy(deep=True)
            for item in (existing or [])
        ]

        for detection in ordered:
            if any(
                detection.detection_id in item.contributing_evidence
                for item in incidents
            ):
                continue

            target = self._find_related(incidents, detection)

            if target is None:
                candidate = self._new_candidate(detection)
                incidents.append(candidate)
            else:
                self._merge(target, detection)

        return sorted(
            (item for item in incidents if self._qualifies(item)),
            key=lambda item: item.incident_id,
        )

    def _find_related(
        self,
        incidents: list[Incident],
        detection: DetectionResult,
    ) -> Incident | None:
        for incident in incidents:
            if incident.application_identity != detection.application_identity:
                continue

            # Rolling-window check: detection must be within correlation_window
            # of the incident's current last_seen.
            if not _within_window(
                incident,
                detection.timestamp,
                self.config.correlation_window,
            ):
                continue

            # Absolute-span check: the total incident duration from first_seen
            # to this detection's timestamp must not exceed max_incident_span.
            # This prevents a long chain of detections — each individually
            # within the rolling window — from creating an unbounded incident.
            if not _within_max_span(
                incident,
                detection.timestamp,
                self.config.max_incident_span,
            ):
                continue

            if _pid_reuse_without_relationship(incident, detection):
                continue

            if (
                _strong_process_match(incident, detection)
                or _category_overlap(incident, detection)
            ):
                return incident

            if (
                incident.timeline
                and incident.timeline[-1].timestamp
                and detection.timestamp
            ):
                return incident

        return None

    def _new_candidate(self, detection: DetectionResult) -> Incident:
        timeline = _timeline_events(detection)
        process_chain = _process_nodes(detection)

        categories = {
            signal.category.value
            for signal in detection.contributing_signals
        }

        return Incident(
            incident_id=_incident_id(detection),
            application_identity=detection.application_identity,
            first_seen=detection.timestamp,
            last_seen=detection.timestamp,
            duration=timedelta(0) if detection.timestamp else None,
            severity=detection.severity,
            confidence=detection.confidence,
            status=IncidentStatus.OPEN,
            anomaly_count=1,
            signal_count=len(detection.contributing_signals),
            affected_processes=(
                [detection.process_guid]
                if detection.process_guid
                else []
            ),
            process_chain=process_chain,
            timeline=timeline,
            contributing_evidence=[detection.detection_id],
        )

    def _qualifies(self, incident: Incident) -> bool:
        categories = {
            event.event_category
            for event in incident.timeline
        }

        return incident.anomaly_count >= self.config.minimum_anomalies and (
            len(categories) >= self.config.minimum_categories
            or _has_process_relationship(incident)
        )

    def _merge(
        self,
        incident: Incident,
        detection: DetectionResult,
    ) -> None:
        # All events for this detection are appended, not just the first.
        # _timeline_events() can now return more than one event per
        # detection (one per (category, signal_type) group), and taking
        # only [0] would silently drop real evidence -- e.g. a
        # new_parent_child_relationship event alongside a
        # new_child_process event in the same "process" category.
        for event in _timeline_events(detection):
            incident.timeline.append(event)
        incident.timeline.sort(key=_timeline_sort_key)

        incident.last_seen = _max_time(
            incident.last_seen,
            detection.timestamp,
        )

        if incident.first_seen and incident.last_seen:
            incident.duration = (
                _utc(incident.last_seen) - _utc(incident.first_seen)
            )

        incident.anomaly_count += 1
        incident.signal_count += len(
            detection.contributing_signals
        )

        incident.contributing_evidence = sorted(
            set(
                incident.contributing_evidence
                + [detection.detection_id]
            )
        )

        if (
            detection.process_guid
            and detection.process_guid
            not in incident.affected_processes
        ):
            incident.affected_processes.append(
                detection.process_guid
            )

        incident.process_chain = _merge_process_nodes(
            incident.process_chain,
            _process_nodes(detection),
        )

        incident.severity = _incident_severity(incident)

        # Evidence-based confidence: replaces the old "+0.05 per merge" formula
        # that could reach 1.0 purely from detection count.
        incident.confidence = _incident_confidence(incident)

        incident.status = IncidentStatus.UPDATED


def _timeline_events(
    detection: DetectionResult,
) -> list[IncidentEvent]:
    """
    One IncidentEvent per distinct (category, signal_type) pair present in
    this detection's contributing_signals -- the same grouping granularity
    backend/ai/evidence.py uses for the AI explanation, not just the
    broader category. This matters because two signal types in the same
    category can mean opposite things (e.g. "process" covers both
    new_child_process -- this app started something new -- and
    new_parent_child_relationship -- this app was started by something
    unusual); grouping only by category would force both into one sentence
    template and misstate which direction the relationship goes.

    Each event's description is built specifically from that group's own
    signals (real program names, real time-of-day) via
    backend.shared.humanize -- the same module the AI explanation layer
    uses -- rather than repeating detection.reason's generic
    "behavioral deviation evidence" / "no significant behavioral deviation"
    text. This is what the frontend's Chronology and Behavioral Evidence
    panels display directly, so fixing it here fixes both panels with no
    frontend change required. Multiple events may share the same
    event_category (e.g. two "process" events) when more than one signal
    type in that category contributed -- the UI already supports this.
    """

    groups: dict[tuple[str, str], list] = {}
    for signal in detection.contributing_signals:
        groups.setdefault((signal.category.value, signal.signal_type), []).append(signal)

    group_keys = sorted(groups) or [("behavior", "")]
    app_basename = humanize.basename(detection.application_identity)

    return [
        IncidentEvent(
            event_reference=detection.detection_id,
            timestamp=detection.timestamp,
            event_category=category,
            process_guid=detection.process_guid,
            parent_process_guid=detection.parent_process_guid,
            description=_signal_group_description(
                category,
                signal_type,
                groups.get((category, signal_type), []),
                detection,
                app_basename,
            ),
            severity=detection.severity,
            contribution=detection.anomaly_score,
            provenance=detection.provenance_references,
        )
        for category, signal_type in group_keys
    ]


def _signal_group_description(
    category: str,
    signal_type: str,
    signals: list,
    detection: DetectionResult,
    app_basename: str | None,
) -> str:
    """
    A specific, plain-language description built from one (category,
    signal_type) group's own signals. Falls back to detection.reason (set
    by backend/detection/engine.py to one of two fixed generic strings)
    only when no signals are available, which should not normally happen
    since groups are derived from these same signals.
    """

    if not signals:
        return detection.reason or "behavioral deviation evidence"

    if category == "temporal":
        # Prefer the properly-localized detection timestamp over the raw
        # stored hour integer -- see the matching comment in
        # backend/ai/evidence.py's _temporal_item for why (UTC-vs-local
        # mismatch between the stored value and what the UI displays).
        time_phrase = humanize.format_hour_from_timestamp(detection.timestamp)
        if time_phrase is None:
            for signal in signals:
                if signal.signal_type == "outside_normal_hour":
                    time_phrase = humanize.format_hour(signal.observed_value)
                    if time_phrase:
                        break
        return humanize.temporal_observation(time_phrase)

    names = humanize.distinct_program_names(
        [signal.observed_value for signal in signals]
    )
    count = len(signals)
    times = "once" if count == 1 else f"{count} times"
    return humanize.specific_observation(signal_type, names, times, app_basename)


def _process_nodes(
    detection: DetectionResult,
) -> list[ProcessNode]:
    if (
        not detection.process_guid
        and not detection.image_path
    ):
        return []

    return [
        ProcessNode(
            process_guid=detection.process_guid,
            process_id=detection.process_id,
            image_path=detection.image_path,
            parent_guid=detection.parent_process_guid,
            start_time=detection.timestamp,
        )
    ]


def _merge_process_nodes(
    existing: list[ProcessNode],
    new: list[ProcessNode],
) -> list[ProcessNode]:
    merged = {
        node.process_guid
        or f"pid:{node.process_id}:{node.image_path}": node
        for node in existing
    }

    for node in new:
        key = (
            node.process_guid
            or f"pid:{node.process_id}:{node.image_path}"
        )
        merged[key] = node

    return sorted(
        merged.values(),
        key=lambda node: (
            node.process_guid or "",
            node.process_id or -1,
            node.image_path or "",
        ),
    )


def _strong_process_match(
    incident: Incident,
    detection: DetectionResult,
) -> bool:
    known = {
        node.process_guid
        for node in incident.process_chain
        if node.process_guid
    }

    return bool(
        detection.process_guid
        and (
            detection.process_guid in known
            or detection.parent_process_guid in known
        )
    )


def _pid_reuse_without_relationship(
    incident: Incident,
    detection: DetectionResult,
) -> bool:
    if (
        not detection.process_guid
        or detection.process_id is None
    ):
        return False

    for node in incident.process_chain:
        if (
            node.process_id == detection.process_id
            and node.process_guid
            and node.process_guid != detection.process_guid
        ):
            return (
                detection.parent_process_guid != node.process_guid
                and node.parent_guid != detection.process_guid
            )

    return False


def _category_overlap(
    incident: Incident,
    detection: DetectionResult,
) -> bool:
    known = {
        event.event_category
        for event in incident.timeline
    }

    current = {
        signal.category.value
        for signal in detection.contributing_signals
    }

    return bool(known & current)


def _has_process_relationship(
    incident: Incident,
) -> bool:
    nodes = incident.process_chain

    known = {
        node.process_guid
        for node in nodes
        if node.process_guid
    }

    if (
        len(known) < 2
        and len(nodes) < incident.anomaly_count
    ):
        return True

    return any(
        node.parent_guid in known
        for node in nodes
        if node.parent_guid
    )


def _utc(value: datetime) -> datetime:
    """
    Normalize a datetime to timezone-aware UTC.

    Existing persisted incidents may contain naive timestamps,
    while newly parsed Sysmon events can contain timezone-aware
    timestamps. Treat legacy naive timestamps as UTC so that
    datetime arithmetic remains consistent.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _within_window(
    incident: Incident,
    timestamp: datetime | None,
    window: timedelta,
) -> bool:
    if timestamp is None or incident.last_seen is None:
        return True

    return abs(
        _utc(timestamp) - _utc(incident.last_seen)
    ) <= window


def _within_max_span(
    incident: Incident,
    timestamp: datetime | None,
    max_span: timedelta,
) -> bool:
    """Return True if adding this detection would not push the incident's total
    span (detection_ts - first_seen) past max_span.

    When first_seen is None the check cannot be applied, so we allow it.
    When timestamp is None there is no way to measure span, so we allow it.
    """
    if timestamp is None or incident.first_seen is None:
        return True

    candidate_span = abs(
        _utc(timestamp) - _utc(incident.first_seen)
    )
    return candidate_span <= max_span


def _incident_confidence(incident: Incident) -> float:
    """Evidence-based confidence score in [0.0, 1.0].

    Scoring logic (each component independently bounded):

    1. Signal category diversity (0 – 0.35)
       Reward genuine variety in detection categories (process, network,
       file, execution, temporal, privilege).  Reaching ≥4 distinct
       categories yields the full 0.35.

    2. Event category diversity (0 – 0.25)
       Reward variety in the incident timeline event categories.
       Reaching ≥3 distinct categories yields the full 0.25.

    3. Process-chain depth (0 – 0.15)
       Reward evidence of actual process relationship chains.

    4. Severity presence (0 – 0.15)
       Reward higher-severity evidence.

    5. Detection count (dampened, 0 – 0.10)
       A small, logarithmically dampened contribution from count.
       Ten or more detections contribute at most 0.10 — so count alone
       cannot push confidence to 1.0.

    Maximum total: 1.0
    Minimum total: 0.0
    """
    # --- 1. Signal category diversity (from timeline event_category values) ---
    all_event_categories = {
        event.event_category for event in incident.timeline
    }
    # Up to 0.35 — each of 4 distinct categories is worth 0.35/4 ≈ 0.0875
    cat_div = min(len(all_event_categories), 4) / 4.0 * 0.35

    # --- 2. Distinct detection-level categories (from signal categories) ---
    # We can infer these from timeline event categories as well (they're the
    # same values).  Reward ≥3 distinct categories up to 0.25.
    event_div = min(len(all_event_categories), 3) / 3.0 * 0.25

    # --- 3. Process chain depth (parent-child links) ---
    chain = incident.process_chain
    known_guids = {
        node.process_guid for node in chain if node.process_guid
    }
    parent_links = sum(
        1
        for node in chain
        if node.parent_guid and node.parent_guid in known_guids
    )
    # Each confirmed parent→child link up to 3 contributes up to 0.05 each.
    process_depth = min(parent_links, 3) / 3.0 * 0.15

    # --- 4. Severity presence ---
    severity_values = {event.severity for event in incident.timeline}

    sev_score = 0.0
    if Severity.HIGH in severity_values:
        sev_score = 0.15
    elif Severity.MEDIUM in severity_values:
        sev_score = 0.10
    elif Severity.LOW in severity_values:
        sev_score = 0.05

    # --- 5. Dampened detection count ---
    # Scales logarithmically from 0 (count=1) toward a max of 0.10 (count>=10).
    # Clamped so that count > 10 never exceeds the 0.10 component maximum.
    count = max(incident.anomaly_count, 1)
    count_score = min(math.log2(count) / math.log2(11), 1.0) * 0.10

    raw = cat_div + event_div + process_depth + sev_score + count_score
    return min(1.0, max(0.0, raw))


def _incident_id(
    detection: DetectionResult,
) -> str:
    return hashlib.sha256(
        f"{detection.application_identity}|"
        f"{detection.detection_id}".encode()
    ).hexdigest()


def _detection_sort_key(
    detection: DetectionResult,
) -> tuple:
    timestamp = (
        _utc(detection.timestamp)
        if detection.timestamp is not None
        else datetime.min.replace(tzinfo=timezone.utc)
    )

    return (
        timestamp,
        detection.detection_id,
    )


def _timeline_sort_key(
    event: IncidentEvent,
) -> tuple:
    timestamp = (
        _utc(event.timestamp)
        if event.timestamp is not None
        else datetime.min.replace(tzinfo=timezone.utc)
    )

    return (
        timestamp,
        event.event_reference,
        event.event_category,
    )


def _max_time(
    first: datetime | None,
    second: datetime | None,
) -> datetime | None:
    if first is None:
        return second

    if second is None:
        return first

    return max(
        _utc(first),
        _utc(second),
    )


def _incident_severity(
    incident: Incident,
) -> Severity:
    categories = {event.event_category for event in incident.timeline}
    severity_values = {event.severity for event in incident.timeline}

    non_normal_categories = {
        event.event_category for event in incident.timeline if event.severity != Severity.NORMAL
    }

    chain = incident.process_chain
    known_guids = {node.process_guid for node in chain if node.process_guid}
    parent_links = sum(
        1 for node in chain
        if node.parent_guid and node.parent_guid in known_guids
        and node.parent_guid != node.process_guid
    )

    has_high = Severity.HIGH in severity_values
    has_medium = Severity.MEDIUM in severity_values
    has_low = Severity.LOW in severity_values

    # 1. HIGH requires strong evidence + corroboration, or medium evidence + high diversity
    if has_high:
        if parent_links >= 1:
            return Severity.HIGH
        if len(non_normal_categories) >= 3:
            return Severity.HIGH

    if has_medium and len(non_normal_categories) >= 3:
        return Severity.HIGH

    # 2. MEDIUM represents meaningful correlated evidence without being critical
    if has_high:
        return Severity.MEDIUM

    if has_medium:
        if parent_links >= 1 or len(non_normal_categories) >= 2:
            return Severity.MEDIUM

    if has_low:
        if len(non_normal_categories) >= 3 or (len(non_normal_categories) >= 2 and parent_links >= 1):
            return Severity.MEDIUM

    # 3. LOW represents limited/weak evidence
    if has_medium:
        return Severity.LOW

    if has_low:
        if parent_links >= 1 or len(categories) >= 2:
            return Severity.LOW
        if incident.anomaly_count >= 2:
            return Severity.LOW

    # 4. NORMAL for baseline/weakest scenarios
    return Severity.NORMAL
