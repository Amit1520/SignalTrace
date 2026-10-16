import hashlib
import re
import xml.etree.ElementTree as ElementTree
from datetime import datetime
from typing import Any

from backend.collector.errors import MalformedEventError, UnsupportedEventError
from backend.collector.source import RawSysmonEvent
from backend.normalization.models import (
    EventKind,
    EventProvenance,
    FileActivityEvent,
    NetworkConnectionEvent,
    NormalizedEvent,
    ProcessCreationEvent,
)

SUPPORTED_EVENT_IDS = {1, 3, 11}
_MAX_XML_BYTES = 2_000_000


def parse_sysmon_event(raw: RawSysmonEvent, max_xml_bytes: int = _MAX_XML_BYTES) -> NormalizedEvent:
    xml_bytes = raw.xml.encode("utf-8")
    if len(xml_bytes) > max_xml_bytes:
        raise MalformedEventError("Sysmon XML exceeded the configured size limit")
    if re.search(r"<!\s*(doctype|entity)", raw.xml, flags=re.IGNORECASE):
        raise MalformedEventError("DOCTYPE and ENTITY declarations are not accepted")

    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError as exc:
        raise MalformedEventError("Sysmon XML could not be parsed") from exc

    system = _child_by_local_name(root, "System")
    event_data = _child_by_local_name(root, "EventData")
    if system is None or event_data is None:
        raise MalformedEventError("Sysmon XML is missing System or EventData")

    event_id_text = _text(_child_by_local_name(system, "EventID"))
    if not event_id_text or not event_id_text.isdigit():
        raise MalformedEventError("Sysmon event ID is missing or invalid")
    event_id = int(event_id_text)
    if event_id not in SUPPORTED_EVENT_IDS:
        raise UnsupportedEventError(f"Sysmon event ID {event_id} is not supported")

    fields = {
        element.attrib.get("Name", ""): (element.text or "").strip()
        for element in event_data
        if element.attrib.get("Name")
    }
    timestamp = _parse_datetime(_attribute(system, "TimeCreated", "SystemTime"))
    record_id = _text(_child_by_local_name(system, "EventRecordID"))
    host = _text(_child_by_local_name(system, "Computer"))
    provider_element = _child_by_local_name(system, "Provider")
    provider = provider_element.attrib.get("Name") if provider_element is not None else None
    provenance = EventProvenance(
        channel=raw.channel,
        provider=provider,
        source_record_id=record_id,
        raw_event_hash=hashlib.sha256(xml_bytes).hexdigest(),
    )
    common: dict[str, Any] = {
        "timestamp": timestamp,
        "host": host,
        "event_id": event_id,
        "record_id": record_id,
        "process_guid": _value(fields, "ProcessGuid"),
        "process_id": _int_value(fields, "ProcessId"),
        "parent_process_guid": _value(fields, "ParentProcessGuid"),
        "parent_process_id": _int_value(fields, "ParentProcessId"),
        "parent_image": _value(fields, "ParentImage"),
        "image": _value(fields, "Image"),
        "command_line": _value(fields, "CommandLine"),
        "hashes": _hashes(_value(fields, "Hashes")),
        "provenance": provenance,
    }
    if event_id == 1:
        return ProcessCreationEvent(
            **common,
            current_directory=_value(fields, "CurrentDirectory"),
            user=_value(fields, "User"),
            integrity_level=_value(fields, "IntegrityLevel"),
        )
    if event_id == 3:
        return NetworkConnectionEvent(
            **common,
            protocol=_value(fields, "Protocol"),
            initiated=_bool_value(fields, "Initiated"),
            source_ip=_value(fields, "SourceIp"),
            source_port=_int_value(fields, "SourcePort"),
            destination_ip=_value(fields, "DestinationIp"),
            destination_hostname=_value(fields, "DestinationHostname"),
            destination_port=_int_value(fields, "DestinationPort"),
        )
    return FileActivityEvent(
        **common,
        target_filename=_value(fields, "TargetFilename"),
        creation_utc=_parse_datetime(_value(fields, "CreationUtc")),
    )


def _child_by_local_name(parent: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((child for child in parent if _local_name(child.tag) == name), None)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ElementTree.Element | None) -> str | None:
    value = element.text.strip() if element is not None and element.text else None
    return value or None


def _attribute(parent: ElementTree.Element, child_name: str, attribute_name: str) -> str | None:
    child = _child_by_local_name(parent, child_name)
    return child.attrib.get(attribute_name) if child is not None else None


def _value(fields: dict[str, str], name: str) -> str | None:
    value = fields.get(name, "").strip()
    return value or None


def _int_value(fields: dict[str, str], name: str) -> int | None:
    value = _value(fields, name)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _bool_value(fields: dict[str, str], name: str) -> bool | None:
    value = _value(fields, name)
    if value is None:
        return None
    if value.lower() in {"true", "1"}:
        return True
    if value.lower() in {"false", "0"}:
        return False
    return None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hashes(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    hashes: dict[str, str] = {}
    for item in value.split(";"):
        if "=" in item:
            name, digest = item.split("=", 1)
            if name.strip() and digest.strip():
                hashes[name.strip().upper()] = digest.strip()
    return hashes
