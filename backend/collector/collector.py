from dataclasses import dataclass, field

from backend.normalization.models import NormalizedEvent
from backend.parser.sysmon import parse_sysmon_event

from .checkpoint import Checkpoint, JsonCheckpointStore
from .config import SysmonCollectorSettings
from .errors import (
    DuplicateEventError,
    EventSourceGapError,
    IngestionError,
    UnsupportedEventError,
)
from .source import SysmonEventSource


@dataclass
class CollectionBatch:
    events: list[NormalizedEvent] = field(default_factory=list)
    errors: list[IngestionError] = field(default_factory=list)
    unsupported_events_skipped: int = 0
    checkpoint: Checkpoint = field(default_factory=Checkpoint)


class ReadOnlySysmonCollector:
    def __init__(
        self,
        source: SysmonEventSource,
        checkpoint_store: JsonCheckpointStore,
        settings: SysmonCollectorSettings | None = None,
    ) -> None:
        self.source = source
        self.checkpoint_store = checkpoint_store
        self.settings = settings or SysmonCollectorSettings()

    def collect_once(self) -> CollectionBatch:
        """
        Collect one batch of Sysmon events.

        IMPORTANT:
        This method does not persist the checkpoint.

        It only returns the highest checkpoint that is safe to commit.
        The ingestion service is responsible for persisting that checkpoint
        after the collected events have been successfully persisted.
        """
        checkpoint = self.checkpoint_store.load_or_reset()
        batch = CollectionBatch(checkpoint=checkpoint)

        seen_record_ids: set[str] = set()

        # Once an event cannot be safely processed, we must not advance the
        # checkpoint beyond that event. Later events may still be collected
        # and persisted, but the checkpoint remains at the last contiguous
        # successfully handled record.
        checkpoint_advancement_blocked = False

        for raw_event in self.source.read_events(
            checkpoint.last_successful_record_id,
            self.settings.batch_size,
        ):
            record_id = _extract_record_id(raw_event.xml)

            try:
                if record_id in seen_record_ids:
                    raise DuplicateEventError(
                        f"event record {record_id} was already processed"
                    )

                if record_id and _is_at_or_before(
                    record_id,
                    checkpoint.last_successful_record_id,
                ):
                    if record_id == checkpoint.last_successful_record_id:
                        raise DuplicateEventError(
                            f"event record {record_id} was already processed"
                        )

                    raise EventSourceGapError(
                        f"event record {record_id} is older than checkpoint "
                        f"{checkpoint.last_successful_record_id}"
                    )

                event = parse_sysmon_event(
                    raw_event,
                    self.settings.max_xml_bytes,
                )

                batch.events.append(event)

                if record_id:
                    seen_record_ids.add(record_id)

                    if not checkpoint_advancement_blocked:
                        checkpoint = Checkpoint(
                            last_successful_record_id=record_id
                        )
                else:
                    # Without a record ID we cannot safely establish a
                    # contiguous checkpoint boundary.
                    checkpoint_advancement_blocked = True

            except UnsupportedEventError:
                # Unsupported events are intentionally skipped rather than
                # treated as ingestion errors. They can advance the
                # checkpoint because they have been successfully examined.
                if record_id:
                    seen_record_ids.add(record_id)

                    if not checkpoint_advancement_blocked:
                        checkpoint = Checkpoint(
                            last_successful_record_id=record_id
                        )
                else:
                    checkpoint_advancement_blocked = True

                batch.unsupported_events_skipped += 1

            except IngestionError as error:
                batch.errors.append(error)

                # Do not advance beyond an event that could not be safely
                # processed. This prevents permanent event loss after a
                # restart or failure.
                checkpoint_advancement_blocked = True

                if record_id:
                    seen_record_ids.add(record_id)

        batch.checkpoint = checkpoint
        return batch


def _is_at_or_before(record_id: str, previous: str | None) -> bool:
    if previous is None:
        return False

    try:
        return int(record_id) <= int(previous)
    except ValueError:
        return record_id == previous


def _extract_record_id(xml: str) -> str | None:
    """Extract EventRecordID from raw Sysmon XML without full parsing."""
    try:
        import xml.etree.ElementTree as ElementTree

        root = ElementTree.fromstring(xml.encode("utf-8"))

        system = next(
            (child for child in root if child.tag.endswith("System")),
            None,
        )

        if system is None:
            return None

        record_id_elem = next(
            (
                child
                for child in system
                if child.tag.endswith("EventRecordID")
            ),
            None,
        )

        return (
            record_id_elem.text.strip()
            if record_id_elem is not None and record_id_elem.text
            else None
        )

    except Exception:
        return None