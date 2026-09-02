from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from . import models


RULE_DIR = Path(__file__).parent / "rules"
SIGMA_COMMIT = "8375f87fc85224a96ec133266ea934a3338246ba"
SIGMA_UPSTREAM = f"https://github.com/SigmaHQ/sigma/blob/{SIGMA_COMMIT}/rules/windows"


def _rule_definition(path: Path) -> dict[str, Any]:
    category = "process_access" if path.name.startswith("proc_access_") else "process_creation"
    return {"path": path, "source_url": f"{SIGMA_UPSTREAM}/{category}/{path.name}"}


# This is a deliberately curated, offline-capable rule pack. Adding a YAML file is enough
# to register it; every rule still has to compile and execute through the real pySigma path.
SIGMA_RULES = tuple(_rule_definition(path) for path in sorted(RULE_DIR.glob("*.yml")))


def load_compiled_rules() -> list[dict[str, Any]]:
    compiled: list[dict[str, Any]] = []
    for definition in SIGMA_RULES:
        yaml_text = definition["path"].read_text(encoding="utf-8")
        collection = SigmaCollection.from_yaml(yaml_text)
        backend = sqliteBackend(processing_pipeline=sysmon_pipeline())
        queries = backend.convert(collection)
        for rule, query in zip(collection.rules, queries, strict=True):
            tags = [str(tag) for tag in rule.tags]
            techniques = [tag.removeprefix("attack.").upper() for tag in tags if tag.startswith("attack.t")]
            technique = max(techniques, key=lambda value: value.count("."), default=None)
            compiled.append(
                {
                    "id": str(rule.id),
                    "name": rule.title,
                    "severity": str(rule.level).rsplit(".", 1)[-1].lower(),
                    "description": rule.description,
                    "mitre_technique": technique,
                    "mitre_techniques": techniques,
                    "tags": tags,
                    "status": str(rule.status).rsplit(".", 1)[-1].lower(),
                    "author": rule.author,
                    "license": "Detection Rule License 1.1",
                    "source_url": definition["source_url"],
                    "yaml_text": yaml_text,
                    "compiled_query": query.replace("<TABLE_NAME>", "sigma_events"),
                    "backend": "pySigma SQLite 1.x",
                    "pipeline": "Official Sysmon pipeline 2.x",
                }
            )
    return compiled


def install_sigma_rules(session: Session) -> list[dict[str, Any]]:
    compiled = load_compiled_rules()
    for item in compiled:
        rule = session.get(models.Rule, item["id"])
        if rule is None:
            rule = models.Rule(
                id=item["id"],
                name=item["name"],
                severity=item["severity"],
                description=item["description"],
                mitre_technique=item["mitre_technique"],
                enabled=True,
            )
            session.add(rule)
        else:
            rule.name = item["name"]
            rule.severity = item["severity"]
            rule.description = item["description"]
            rule.mitre_technique = item["mitre_technique"]
        session.merge(
            models.SigmaRuleArtifact(
                rule_id=item["id"],
                status=item["status"],
                author=item["author"],
                license=item["license"],
                source_url=item["source_url"],
                yaml_text=item["yaml_text"],
                compiled_query=item["compiled_query"],
                backend=item["backend"],
                pipeline=item["pipeline"],
                tags=item["tags"],
                techniques=item["mitre_techniques"],
                compatibility="compatible",
                last_error=None,
            )
        )
    session.flush()
    return compiled


def run_sigma_detections(session: Session) -> dict[str, Any]:
    compiled = install_sigma_rules(session)
    rules_by_id = {item["id"]: item for item in compiled}
    signal_pairs: set[tuple[str, str]] = set()
    errors: list[dict[str, str]] = []
    for item in compiled:
        rule = session.get(models.Rule, item["id"])
        if rule is not None and not rule.enabled:
            continue
        try:
            rows = session.execute(text(item["compiled_query"])).mappings().all()
        except Exception as error:  # rule-level isolation; diagnostics are returned to the caller
            artifact = session.get(models.SigmaRuleArtifact, item["id"])
            if artifact:
                artifact.compatibility = "query_error"
                artifact.last_error = str(error)
            errors.append({"rule_id": item["id"], "error": str(error)})
            continue
        artifact = session.get(models.SigmaRuleArtifact, item["id"])
        if artifact:
            artifact.compatibility = "compatible"
            artifact.last_error = None
        event_ids = list(dict.fromkeys(row["event_id"] for row in rows))
        signal_pairs.update((item["id"], event_id) for event_id in event_ids)

    matched_event_ids = {event_id for _, event_id in signal_pairs}
    events = session.scalars(
        select(models.NormalizedEvent).where(models.NormalizedEvent.id.in_(matched_event_ids))
    ).all() if matched_event_ids else []
    events_by_id = {event.id: event for event in events}
    clusters: dict[str, dict[str, Any]] = {}
    for rule_id, event_id in sorted(signal_pairs):
        event = events_by_id[event_id]
        process_name = (event.process or "unknown").replace("/", "\\").rsplit("\\", 1)[-1].lower()
        bucket = event.timestamp.replace(minute=0, second=0, microsecond=0)
        fingerprint = "|".join((event.source, event.host or "unknown", process_name, bucket.isoformat()))
        correlation_key = hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
        cluster = clusters.setdefault(
            correlation_key,
            {
                "fingerprint": fingerprint,
                "signals": set(),
                "event_ids": set(),
                "rule_ids": set(),
            },
        )
        cluster["signals"].add((rule_id, event_id))
        cluster["event_ids"].add(event_id)
        cluster["rule_ids"].add(rule_id)

    severity_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    existing = {
        finding.correlation_key: finding
        for finding in session.scalars(select(models.Finding))
        if finding.correlation_key
    }
    # Signals are a deterministic materialized result of the current rule/event state.
    # Rebuild the projection atomically so a signal can move between correlation groups
    # without colliding with its previous unique (rule_id, event_id) row.
    session.execute(delete(models.DetectionSignal))
    next_number = max(
        (int(finding_id.removeprefix("F-")) for finding_id in session.scalars(select(models.Finding.id)) if finding_id.removeprefix("F-").isdigit()),
        default=0,
    )
    created = 0
    updated = 0
    for correlation_key, cluster in clusters.items():
        cluster_events = sorted(
            (events_by_id[event_id] for event_id in cluster["event_ids"]),
            key=lambda event: (event.timestamp, event.id),
        )
        cluster_rules = sorted(
            (rules_by_id[rule_id] for rule_id in cluster["rule_ids"]),
            key=lambda item: (
                severity_rank.get(item["severity"], 0),
                item["status"] == "stable",
                item["name"],
            ),
            reverse=True,
        )
        primary = cluster_rules[0]
        signal_count = len(cluster["signals"])
        event_count = len(cluster_events)
        duplicate_count = signal_count - event_count
        rule_count = len(cluster_rules)
        severity = primary["severity"]
        risk_score = min(100, 25 + severity_rank.get(severity, 0) * 14 + min(20, (rule_count - 1) * 3) + min(12, event_count // 4))
        confidence = min(99, 52 + (10 if any(item["status"] == "stable" for item in cluster_rules) else 0) + min(24, rule_count * 3) + min(10, duplicate_count // 3))
        entities = {
            "hosts": sorted({event.host for event in cluster_events if event.host}),
            "users": sorted({event.user for event in cluster_events if event.user}),
            "processes": sorted({event.process for event in cluster_events if event.process}),
        }
        finding = existing.get(correlation_key)
        if finding is None:
            next_number += 1
            finding = models.Finding(
                id=f"F-{next_number:03d}",
                rule_id=primary["id"],
                title=primary["name"],
                severity=severity,
                description=primary["description"],
                timestamp=cluster_events[-1].timestamp,
                correlation_key=correlation_key,
            )
            session.add(finding)
            session.flush()
            created += 1
        else:
            session.execute(delete(models.FindingEvent).where(models.FindingEvent.finding_id == finding.id))
            updated += 1
        finding.rule_id = primary["id"]
        finding.title = primary["name"] if rule_count == 1 else f"{primary['name']} + {rule_count - 1} related detections"
        finding.severity = severity
        finding.description = (
            f"{primary['description']} Correlated from {rule_count} Sigma rules across "
            f"{event_count} distinct events in one host, process, and one-hour activity window."
        )
        finding.timestamp = cluster_events[-1].timestamp
        finding.status = "NEW" if finding.status == "STALE" else finding.status
        finding.entities = entities
        finding.rule_ids = [item["id"] for item in cluster_rules]
        finding.risk_score = risk_score
        finding.confidence = confidence
        finding.first_seen = cluster_events[0].timestamp
        finding.last_seen = cluster_events[-1].timestamp
        finding.signal_count = signal_count
        finding.suppressed_signal_count = duplicate_count
        session.add_all(models.FindingEvent(finding_id=finding.id, event_id=event.id) for event in cluster_events)
        session.add_all(
            models.DetectionSignal(finding_id=finding.id, rule_id=rule_id, event_id=event_id)
            for rule_id, event_id in sorted(cluster["signals"])
        )

    desired_keys = set(clusters)
    for finding in session.scalars(select(models.Finding)).all():
        if finding.correlation_key in desired_keys:
            continue
        protected = session.scalar(
            select(models.Investigation.id).where(models.Investigation.finding_id == finding.id).limit(1)
        )
        if protected:
            finding.status = "STALE"
        else:
            session.delete(finding)
    matched_rules = len({rule_id for rule_id, _ in signal_pairs})
    enabled_rules = sum(session.get(models.Rule, item["id"]).enabled for item in compiled)
    session.flush()
    return {
        "rules_evaluated": enabled_rules,
        "matched_rules": matched_rules,
        "matched_events": len(signal_pairs),
        "distinct_events": len(matched_event_ids),
        "triage_groups": len(clusters),
        "suppressed_duplicates": len(signal_pairs) - len(matched_event_ids),
        "findings_created": created,
        "findings_updated": updated,
        "errors": errors,
    }
