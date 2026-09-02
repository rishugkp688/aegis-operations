from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from defusedxml import ElementTree

from . import models


DATA_DIR = Path(__file__).parent / "data"


@dataclass(frozen=True)
class DatasetDefinition:
    id: str
    name: str
    technique: str
    path: Path
    source: str
    event_prefix: str
    available_events: int
    provenance: str
    source_url: str


DATASETS = (
    DatasetDefinition(
        id="splunk-t1003-001",
        name="Credential Dumping: LSASS Memory",
        technique="T1003.001",
        path=DATA_DIR / "splunk_t1003_001_sysmon.log",
        source="splunk_attack_data_t1003_001",
        event_prefix="LSA",
        available_events=7960,
        provenance="Attack Range / Atomic Red Team T1003.001",
        source_url="https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1003.001/atomic_red_team",
    ),
    DatasetDefinition(
        id="splunk-t1059-001",
        name="Encoded PowerShell Execution",
        technique="T1059.001",
        path=DATA_DIR / "splunk_t1059_001_encoded_powershell_sysmon.log",
        source="splunk_attack_data_t1059_001",
        event_prefix="PSE",
        available_events=1185,
        provenance="Attack Range / encoded PowerShell T1059.001",
        source_url="https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1059.001/encoded_powershell",
    ),
    DatasetDefinition(
        id="splunk-t1105",
        name="Ingress Tool Transfer",
        technique="T1105",
        path=DATA_DIR / "splunk_t1105_sysmon.log",
        source="splunk_attack_data_t1105",
        event_prefix="IFT",
        available_events=2290,
        provenance="Attack Range / Atomic Red Team T1105",
        source_url="https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1105/atomic_red_team",
    ),
)
DATASET_BY_ID = {dataset.id: dataset for dataset in DATASETS}

EVENT_TYPES = {
    1: "process_start",
    3: "network_connection",
    4: "sysmon_service_state",
    5: "process_terminated",
    6: "driver_loaded",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_create",
    12: "registry_object",
    13: "registry_value_set",
    16: "sysmon_config_change",
    22: "dns_query",
}


@dataclass(frozen=True)
class ParsedSysmonEvent:
    event_id: int
    timestamp: datetime
    record_id: str
    channel: str | None
    computer: str | None
    data: dict[str, str]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_sysmon_xml(xml_text: str) -> ParsedSysmonEvent:
    root = ElementTree.fromstring(xml_text)
    system = next((node for node in root if _local_name(node.tag) == "System"), None)
    if system is None:
        raise ValueError("Windows event has no System element")

    system_values: dict[str, str] = {}
    timestamp: str | None = None
    for node in system:
        name = _local_name(node.tag)
        if name == "TimeCreated":
            timestamp = node.attrib.get("SystemTime")
        elif node.text:
            system_values[name] = node.text

    data: dict[str, str] = {}
    for section in root:
        if _local_name(section.tag) != "EventData":
            continue
        for node in section:
            if _local_name(node.tag) == "Data" and node.attrib.get("Name"):
                data[node.attrib["Name"]] = node.text or ""

    if not timestamp:
        timestamp = data.get("UtcTime")
    if not timestamp:
        raise ValueError("Windows event has no timestamp")
    parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return ParsedSysmonEvent(
        event_id=int(system_values["EventID"]),
        timestamp=parsed_time,
        record_id=system_values.get("EventRecordID", "unknown"),
        channel=system_values.get("Channel"),
        computer=system_values.get("Computer"),
        data=data,
    )


def iter_splunk_sysmon(path: Path | None = None) -> Iterator[tuple[str, ParsedSysmonEvent]]:
    path = path or DATASETS[0].path
    buffer = ""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            buffer += line
            while "</Event>" in buffer:
                record, buffer = buffer.split("</Event>", 1)
                raw = f"{record}</Event>".strip()
                if raw:
                    yield raw, parse_sysmon_xml(raw)
    if buffer.strip():
        raise ValueError("Dataset ended with an incomplete Windows event")


def normalized_from_sysmon(
    raw_id: int,
    parsed: ParsedSysmonEvent,
    sequence: int,
    dataset: DatasetDefinition,
) -> models.NormalizedEvent:
    data = parsed.data
    process = data.get("Image") or data.get("SourceImage")
    return models.NormalizedEvent(
        id=f"{dataset.event_prefix}-{sequence:06d}",
        timestamp=parsed.timestamp,
        source=dataset.source,
        event_type=EVENT_TYPES.get(parsed.event_id, f"sysmon_event_{parsed.event_id}"),
        host=parsed.computer,
        user=data.get("User") or data.get("SourceUser"),
        process=process,
        parent_process=data.get("ParentImage"),
        source_ip=data.get("SourceIp"),
        destination_ip=data.get("DestinationIp"),
        command_line=data.get("CommandLine"),
        additional_fields={
            "EventID": parsed.event_id,
            "Channel": parsed.channel,
            "EventRecordID": parsed.record_id,
            **data,
        },
        raw_log_id=raw_id,
    )


SIGMA_FIELDS = (
    "Image",
    "CommandLine",
    "ParentImage",
    "User",
    "SourceImage",
    "TargetImage",
    "GrantedAccess",
    "CallTrace",
    "TargetFilename",
    "DestinationIp",
    "DestinationPort",
    "QueryName",
    "Hashes",
    "IntegrityLevel",
    "OriginalFileName",
    "ParentCommandLine",
)


def sigma_projection(event_id: str, parsed: ParsedSysmonEvent) -> models.SigmaEvent:
    values: dict[str, Any] = {field: parsed.data.get(field) for field in SIGMA_FIELDS}
    return models.SigmaEvent(
        event_id=event_id,
        EventID=parsed.event_id,
        Channel=parsed.channel,
        Computer=parsed.computer,
        UtcTime=parsed.data.get("UtcTime") or parsed.timestamp.isoformat(),
        **values,
    )
