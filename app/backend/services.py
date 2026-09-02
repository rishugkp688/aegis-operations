from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import String, and_, cast, delete, func, or_, select
from sqlalchemy.orm import Session, selectinload

from . import models
from .ingestion import (
    DATASETS,
    DATASET_BY_ID,
    iter_splunk_sysmon,
    normalized_from_sysmon,
    sigma_projection,
)
from .schemas import (
    AddEvidenceRequest,
    AggregateRequest,
    CreateHypothesisRequest,
    SearchEventsRequest,
    UpdateHypothesisRequest,
)
from .sigma_engine import SIGMA_RULES, install_sigma_rules, load_compiled_rules, run_sigma_detections


def _event_dict(event: models.NormalizedEvent, include_raw: bool = False) -> dict[str, Any]:
    result = {
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "host": event.host,
        "user": event.user,
        "process": event.process,
        "parent_process": event.parent_process,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "command_line": event.command_line,
        "additional_fields": event.additional_fields,
    }
    if include_raw:
        try:
            result["raw"] = json.loads(event.raw_log.raw_text)
        except json.JSONDecodeError:
            result["raw"] = event.raw_log.raw_text
    return result


def _finding_dict(finding: models.Finding, include_events: bool = False) -> dict[str, Any]:
    artifact = finding.rule.sigma_artifact
    result = {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule.name,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "timestamp": finding.timestamp.isoformat(),
        "status": finding.status,
        "entities": finding.entities,
        "mitre_technique": finding.rule.mitre_technique,
        "matched_event_count": len(finding.event_links),
        "signal_count": finding.signal_count or len(finding.event_links),
        "suppressed_signal_count": finding.suppressed_signal_count or 0,
        "rule_ids": finding.rule_ids or [finding.rule_id],
        "rule_count": len(finding.rule_ids or [finding.rule_id]),
        "risk_score": finding.risk_score or 0,
        "confidence": finding.confidence or 0,
        "first_seen": (finding.first_seen or finding.timestamp).isoformat(),
        "last_seen": (finding.last_seen or finding.timestamp).isoformat(),
        "event_ids": [link.event_id for link in finding.event_links],
        "engine": "sigma" if artifact else "native",
        "sigma": (
            {
                "status": artifact.status,
                "author": artifact.author,
                "license": artifact.license,
                "source_url": artifact.source_url,
                "backend": artifact.backend,
                "pipeline": artifact.pipeline,
                "compiled_query": artifact.compiled_query,
                "tags": artifact.tags or [],
                "techniques": artifact.techniques or [],
            }
            if artifact
            else None
        ),
    }
    if include_events:
        result["events"] = [_event_dict(link.event, include_raw=True) for link in finding.event_links]
    return result


def _next_id(session: Session, model: type[Any], prefix: str) -> str:
    count = session.scalar(select(func.count()).select_from(model)) or 0
    return f"{prefix}-{count + 1:03d}"


def _audit(
    session: Session,
    investigation_id: str,
    event_type: str,
    actor: str,
    summary: str,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(
        models.InvestigationEvent(
            investigation_id=investigation_id,
            event_type=event_type,
            actor=actor,
            summary=summary,
            detail=detail or {},
        )
    )


def workspace_status(session: Session) -> dict[str, Any]:
    active_finding_statuses = ("NEW", "INVESTIGATING")
    counts = {
        "raw_logs": session.scalar(select(func.count()).select_from(models.RawLog)) or 0,
        "normalized_events": session.scalar(select(func.count()).select_from(models.NormalizedEvent)) or 0,
        "rules": session.scalar(select(func.count()).select_from(models.Rule)) or 0,
        "findings": session.scalar(
            select(func.count()).select_from(models.Finding).where(models.Finding.status != "STALE")
        ) or 0,
        "open_findings": session.scalar(
            select(func.count()).select_from(models.Finding).where(models.Finding.status.in_(active_finding_statuses))
        ) or 0,
        "investigations": session.scalar(select(func.count()).select_from(models.Investigation)) or 0,
        "open_investigations": session.scalar(
            select(func.count()).select_from(models.Investigation).where(models.Investigation.status == "OPEN")
        ) or 0,
    }
    matched_sigma_rules = session.scalar(
        select(func.count(func.distinct(models.DetectionSignal.rule_id)))
        .select_from(models.DetectionSignal)
        .join(models.Finding, models.Finding.id == models.DetectionSignal.finding_id)
        .where(models.Finding.status != "STALE")
    ) or 0
    signal_count = session.scalar(
        select(func.count())
        .select_from(models.DetectionSignal)
        .join(models.Finding, models.Finding.id == models.DetectionSignal.finding_id)
        .where(models.Finding.status != "STALE")
    ) or 0
    distinct_detected_events = session.scalar(
        select(func.count(func.distinct(models.DetectionSignal.event_id)))
        .select_from(models.DetectionSignal)
        .join(models.Finding, models.Finding.id == models.DetectionSignal.finding_id)
        .where(models.Finding.status != "STALE")
    ) or 0
    return {
        "application": "aegis-operations",
        "dataset": "Splunk Attack Data detection lab",
        "ingested": counts["raw_logs"] > 0,
        "counts": counts,
        "webmcp_tools": 8,
        "datasets": list_datasets(session),
        "detection_engine": {
            "name": "pySigma",
            "backend": "SQLite",
            "pipeline": "Sysmon",
            "official_rules": session.scalar(select(func.count()).select_from(models.SigmaRuleArtifact)) or 0,
            "available_rules": len(SIGMA_RULES),
            "enabled_rules": session.scalar(
                select(func.count()).select_from(models.Rule).where(models.Rule.enabled.is_(True))
            ) or len(SIGMA_RULES),
            "matched_rules": matched_sigma_rules,
            "signal_count": signal_count,
            "distinct_detected_events": distinct_detected_events,
            "suppressed_duplicates": max(0, signal_count - distinct_detected_events),
        },
    }


def list_datasets(session: Session) -> list[dict[str, Any]]:
    items = []
    for dataset in DATASETS:
        ingested_count = session.scalar(
            select(func.count()).select_from(models.RawLog).where(models.RawLog.source == dataset.source)
        ) or 0
        items.append(
            {
                "id": dataset.id,
                "name": dataset.name,
                "provider": "Splunk Attack Data",
                "telemetry": "Windows Sysmon XML",
                "technique": dataset.technique,
                "provenance": dataset.provenance,
                "license": "Apache-2.0",
                "source_url": dataset.source_url,
                "available_events": dataset.available_events,
                "ingested_events": ingested_count,
                "ingested": ingested_count > 0,
                "local_file": dataset.path.name,
            }
        )
    return items


def ingest_dataset(session: Session, dataset_id: str) -> dict[str, Any]:
    dataset = DATASET_BY_ID.get(dataset_id)
    if not dataset:
        raise HTTPException(404, f"Dataset {dataset_id} not found")
    if session.scalar(select(models.RawLog.id).where(models.RawLog.source == dataset.source).limit(1)):
        status = workspace_status(session)
        return {**status, "already_ingested": True, "accepted": 0, "rejected": 0}

    accepted: list[tuple[models.RawLog, Any, int]] = []
    rejected = 0
    sequence = 0
    for raw_text, parsed in iter_splunk_sysmon(dataset.path):
        sequence += 1
        try:
            raw = models.RawLog(
                source_record_id=f"{dataset.id}-{sequence:06d}",
                source=dataset.source,
                raw_text=raw_text,
            )
            accepted.append((raw, parsed, sequence))
        except (KeyError, TypeError, ValueError):
            rejected += 1

    session.add_all(raw for raw, _, _ in accepted)
    session.flush()
    normalized: list[models.NormalizedEvent] = []
    projections: list[models.SigmaEvent] = []
    for raw, parsed, item_sequence in accepted:
        event = normalized_from_sysmon(raw.id, parsed, item_sequence, dataset)
        normalized.append(event)
        projections.append(sigma_projection(event.id, parsed))
    session.add_all(normalized)
    session.flush()
    session.add_all(projections)
    session.flush()
    detection_run = run_sigma_detections(session)
    session.commit()
    return {
        **workspace_status(session),
        "already_ingested": False,
        "accepted": len(accepted),
        "rejected": rejected,
        "detection_run": detection_run,
    }


def list_sigma_rules(session: Session) -> list[dict[str, Any]]:
    finding_counts = dict(
        session.execute(
            select(models.DetectionSignal.rule_id, func.count(models.DetectionSignal.id))
            .join(models.Finding, models.Finding.id == models.DetectionSignal.finding_id)
            .where(models.Finding.status != "STALE")
            .group_by(models.DetectionSignal.rule_id)
        ).all()
    )
    stored = {
        rule.id: rule
        for rule in session.scalars(select(models.Rule).options(selectinload(models.Rule.sigma_artifact)))
    }
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "severity": item["severity"],
            "status": item["status"],
            "author": item["author"],
            "mitre_technique": item["mitre_technique"],
            "mitre_techniques": item["mitre_techniques"],
            "source_url": item["source_url"],
            "backend": item["backend"],
            "pipeline": item["pipeline"],
            "match_count": finding_counts.get(item["id"], 0),
            "enabled": stored[item["id"]].enabled if item["id"] in stored else True,
            "compatibility": (
                stored[item["id"]].sigma_artifact.compatibility
                if item["id"] in stored and stored[item["id"]].sigma_artifact
                else "compatible"
            ),
            "last_error": (
                stored[item["id"]].sigma_artifact.last_error
                if item["id"] in stored and stored[item["id"]].sigma_artifact
                else None
            ),
        }
        for item in load_compiled_rules()
    ]


def set_sigma_rule_state(session: Session, rule_id: str, enabled: bool) -> dict[str, Any]:
    install_sigma_rules(session)
    rule = session.get(models.Rule, rule_id)
    if not rule or not rule.sigma_artifact:
        raise HTTPException(404, f"Sigma rule {rule_id} not found")
    rule.enabled = enabled
    session.flush()
    detection_run = run_sigma_detections(session)
    session.commit()
    selected = next(item for item in list_sigma_rules(session) if item["id"] == rule_id)
    return {
        "rule": selected,
        "detection_run": detection_run,
        "workspace": workspace_status(session),
    }


def reset_workspace(session: Session) -> dict[str, Any]:
    removed = workspace_status(session)["counts"]
    for model in (
        models.Incident,
        models.InvestigationEvent,
        models.Hypothesis,
        models.Evidence,
        models.Investigation,
        models.DetectionSignal,
        models.FindingEvent,
        models.Finding,
        models.SigmaRuleArtifact,
        models.Rule,
        models.SigmaEvent,
        models.NormalizedEvent,
        models.RawLog,
    ):
        session.execute(delete(model))
    session.commit()
    return {"reset": True, "removed": removed, "workspace": workspace_status(session)}


def search_events(session: Session, filters: SearchEventsRequest) -> dict[str, Any]:
    clauses = []
    if filters.host:
        clauses.append(models.NormalizedEvent.host == filters.host)
    if filters.user:
        clauses.append(models.NormalizedEvent.user == filters.user)
    if filters.process:
        clauses.append(models.NormalizedEvent.process.ilike(f"%{filters.process}%"))
    if filters.event_type:
        clauses.append(models.NormalizedEvent.event_type == filters.event_type)
    if filters.query:
        needle = f"%{filters.query}%"
        clauses.append(
            or_(
                models.NormalizedEvent.command_line.ilike(needle),
                models.NormalizedEvent.process.ilike(needle),
                models.NormalizedEvent.parent_process.ilike(needle),
                models.NormalizedEvent.user.ilike(needle),
                models.NormalizedEvent.host.ilike(needle),
                models.NormalizedEvent.destination_ip.ilike(needle),
                cast(models.NormalizedEvent.additional_fields, String).ilike(needle),
            )
        )
    where_clause = and_(*clauses) if clauses else None
    count_stmt = select(func.count()).select_from(models.NormalizedEvent)
    data_stmt = (
        select(models.NormalizedEvent)
        .options(selectinload(models.NormalizedEvent.raw_log))
        .order_by(models.NormalizedEvent.timestamp.desc(), models.NormalizedEvent.id.desc())
        .offset(filters.offset)
        .limit(filters.limit)
    )
    if where_clause is not None:
        count_stmt = count_stmt.where(where_clause)
        data_stmt = data_stmt.where(where_clause)
    total = session.scalar(count_stmt) or 0
    events = session.scalars(data_stmt).all()
    return {"total": total, "limit": filters.limit, "offset": filters.offset, "items": [_event_dict(e) for e in events]}


def get_event(session: Session, event_id: str) -> dict[str, Any]:
    event = session.scalar(
        select(models.NormalizedEvent)
        .where(models.NormalizedEvent.id == event_id)
        .options(selectinload(models.NormalizedEvent.raw_log))
    )
    if not event:
        raise HTTPException(404, f"Event {event_id} not found")
    result = _event_dict(event, include_raw=True)
    result["finding_ids"] = list(
        session.scalars(select(models.FindingEvent.finding_id).where(models.FindingEvent.event_id == event_id))
    )
    return result


def get_event_context(session: Session, event_id: str, before: int, after: int) -> dict[str, Any]:
    target = session.get(models.NormalizedEvent, event_id)
    if not target:
        raise HTTPException(404, f"Event {event_id} not found")
    previous = list(
        session.scalars(
            select(models.NormalizedEvent)
            .where(models.NormalizedEvent.timestamp < target.timestamp)
            .order_by(models.NormalizedEvent.timestamp.desc())
            .limit(before)
        )
    )[::-1]
    following = list(
        session.scalars(
            select(models.NormalizedEvent)
            .where(models.NormalizedEvent.timestamp > target.timestamp)
            .order_by(models.NormalizedEvent.timestamp)
            .limit(after)
        )
    )
    events = [*previous, target, *following]
    return {"target_event_id": event_id, "items": [_event_dict(event) for event in events]}


def aggregate_activity(session: Session, request: AggregateRequest) -> dict[str, Any]:
    column = getattr(models.NormalizedEvent, request.group_by)
    latest = session.scalar(select(func.max(models.NormalizedEvent.timestamp)))
    clauses = [column.is_not(None)]
    if latest:
        clauses.append(models.NormalizedEvent.timestamp >= latest - timedelta(minutes=request.minutes))
    if request.host:
        clauses.append(models.NormalizedEvent.host == request.host)
    if request.user:
        clauses.append(models.NormalizedEvent.user == request.user)
    rows = session.execute(
        select(column, func.count(models.NormalizedEvent.id))
        .where(and_(*clauses))
        .group_by(column)
        .order_by(func.count(models.NormalizedEvent.id).desc())
        .limit(request.limit)
    ).all()
    return {
        "group_by": request.group_by,
        "window_minutes": request.minutes,
        "items": [{"value": value, "count": count} for value, count in rows],
    }


def list_findings(session: Session) -> list[dict[str, Any]]:
    findings = session.scalars(
        select(models.Finding)
        .where(models.Finding.status != "STALE")
        .options(
            selectinload(models.Finding.rule).selectinload(models.Rule.sigma_artifact),
            selectinload(models.Finding.event_links),
        )
        .order_by(models.Finding.timestamp.desc())
    ).all()
    return [_finding_dict(finding) for finding in findings]


def get_finding(session: Session, finding_id: str) -> dict[str, Any]:
    finding = session.scalar(
        select(models.Finding)
        .where(models.Finding.id == finding_id)
        .options(
            selectinload(models.Finding.rule),
            selectinload(models.Finding.rule).selectinload(models.Rule.sigma_artifact),
            selectinload(models.Finding.event_links).selectinload(models.FindingEvent.event).selectinload(models.NormalizedEvent.raw_log),
        )
    )
    if not finding:
        raise HTTPException(404, f"Finding {finding_id} not found")
    return _finding_dict(finding, include_events=True)


def start_investigation(session: Session, finding_id: str, actor: str) -> dict[str, Any]:
    finding = session.get(models.Finding, finding_id)
    if not finding:
        raise HTTPException(404, f"Finding {finding_id} not found")
    existing = session.scalar(select(models.Investigation).where(models.Investigation.finding_id == finding_id))
    if existing:
        return get_investigation(session, existing.id)
    investigation = models.Investigation(id=_next_id(session, models.Investigation, "INV"), finding_id=finding_id)
    session.add(investigation)
    session.flush()
    _audit(session, investigation.id, "INVESTIGATION_CREATED", actor, f"Investigation opened for {finding_id}")
    finding.status = "INVESTIGATING"
    session.commit()
    return get_investigation(session, investigation.id)


def list_investigations(session: Session) -> list[dict[str, Any]]:
    investigations = session.scalars(select(models.Investigation).order_by(models.Investigation.updated_at.desc())).all()
    return [get_investigation(session, item.id) for item in investigations]


def get_investigation(session: Session, investigation_id: str) -> dict[str, Any]:
    investigation = session.scalar(
        select(models.Investigation)
        .where(models.Investigation.id == investigation_id)
        .options(
            selectinload(models.Investigation.finding).selectinload(models.Finding.rule),
            selectinload(models.Investigation.finding)
            .selectinload(models.Finding.rule)
            .selectinload(models.Rule.sigma_artifact),
            selectinload(models.Investigation.finding).selectinload(models.Finding.event_links),
            selectinload(models.Investigation.evidence).selectinload(models.Evidence.event),
            selectinload(models.Investigation.hypotheses),
            selectinload(models.Investigation.events),
        )
    )
    if not investigation:
        raise HTTPException(404, f"Investigation {investigation_id} not found")
    return {
        "id": investigation.id,
        "status": investigation.status,
        "verdict": investigation.verdict,
        "created_at": investigation.created_at.isoformat(),
        "updated_at": investigation.updated_at.isoformat(),
        "finding": _finding_dict(investigation.finding),
        "evidence": [
            {
                "id": item.id,
                "event_id": item.event_id,
                "rationale": item.rationale,
                "added_by": item.added_by,
                "created_at": item.created_at.isoformat(),
                "event": _event_dict(item.event),
            }
            for item in sorted(investigation.evidence, key=lambda item: item.created_at)
        ],
        "hypotheses": [
            {
                "id": item.id,
                "title": item.title,
                "reasoning": item.reasoning,
                "status": item.status,
                "confidence": item.confidence,
                "evidence_ids": item.evidence_ids,
                "created_by": item.created_by,
                "created_at": item.created_at.isoformat(),
                "updated_at": item.updated_at.isoformat(),
            }
            for item in sorted(investigation.hypotheses, key=lambda item: item.created_at)
        ],
        "timeline": [
            {
                "id": item.id,
                "event_type": item.event_type,
                "actor": item.actor,
                "summary": item.summary,
                "detail": item.detail,
                "created_at": item.created_at.isoformat(),
            }
            for item in sorted(investigation.events, key=lambda item: item.created_at, reverse=True)
        ],
    }


def _require_open_investigation(investigation: models.Investigation) -> None:
    if investigation.status != "OPEN":
        raise HTTPException(409, f"Investigation {investigation.id} is closed and read-only")


def add_evidence(session: Session, investigation_id: str, request: AddEvidenceRequest) -> dict[str, Any]:
    investigation = session.get(models.Investigation, investigation_id)
    if not investigation:
        raise HTTPException(404, f"Investigation {investigation_id} not found")
    _require_open_investigation(investigation)
    found_ids = set(session.scalars(select(models.NormalizedEvent.id).where(models.NormalizedEvent.id.in_(request.event_ids))))
    missing = set(request.event_ids) - found_ids
    if missing:
        raise HTTPException(422, f"Unknown event IDs: {', '.join(sorted(missing))}")
    existing_ids = set(
        session.scalars(select(models.Evidence.event_id).where(models.Evidence.investigation_id == investigation_id))
    )
    created_ids = []
    for event_id in request.event_ids:
        if event_id in existing_ids:
            continue
        evidence_id = _next_id(session, models.Evidence, "EV")
        session.add(
            models.Evidence(
                id=evidence_id,
                investigation_id=investigation_id,
                event_id=event_id,
                rationale=request.rationale,
                added_by=request.actor,
            )
        )
        session.flush()
        created_ids.append(evidence_id)
    _audit(
        session,
        investigation_id,
        "EVIDENCE_ADDED",
        request.actor,
        f"Added {len(created_ids)} event(s) as evidence",
        {"evidence_ids": created_ids, "event_ids": request.event_ids, "rationale": request.rationale},
    )
    session.commit()
    return {"created_evidence_ids": created_ids, "investigation": get_investigation(session, investigation_id)}


def create_hypothesis(
    session: Session, investigation_id: str, request: CreateHypothesisRequest
) -> dict[str, Any]:
    investigation = session.get(models.Investigation, investigation_id)
    if not investigation:
        raise HTTPException(404, f"Investigation {investigation_id} not found")
    _require_open_investigation(investigation)
    valid_evidence = set(
        session.scalars(select(models.Evidence.id).where(models.Evidence.investigation_id == investigation_id))
    )
    invalid = set(request.evidence_ids) - valid_evidence
    if invalid:
        raise HTTPException(422, f"Evidence does not belong to investigation: {', '.join(sorted(invalid))}")
    hypothesis = models.Hypothesis(
        id=_next_id(session, models.Hypothesis, "H"),
        investigation_id=investigation_id,
        title=request.title,
        reasoning=request.reasoning,
        confidence=request.confidence,
        evidence_ids=request.evidence_ids,
        created_by=request.actor,
    )
    session.add(hypothesis)
    session.flush()
    _audit(
        session,
        investigation_id,
        "HYPOTHESIS_CREATED",
        request.actor,
        f"Created hypothesis {hypothesis.id}: {hypothesis.title}",
        {"hypothesis_id": hypothesis.id, "evidence_ids": request.evidence_ids},
    )
    session.commit()
    return {"hypothesis_id": hypothesis.id, "investigation": get_investigation(session, investigation_id)}


def update_hypothesis(
    session: Session,
    investigation_id: str,
    hypothesis_id: str,
    request: UpdateHypothesisRequest,
) -> dict[str, Any]:
    investigation = session.get(models.Investigation, investigation_id)
    if not investigation:
        raise HTTPException(404, f"Investigation {investigation_id} not found")
    _require_open_investigation(investigation)
    hypothesis = session.scalar(
        select(models.Hypothesis).where(
            models.Hypothesis.id == hypothesis_id,
            models.Hypothesis.investigation_id == investigation_id,
        )
    )
    if not hypothesis:
        raise HTTPException(404, f"Hypothesis {hypothesis_id} not found")
    changes = request.model_dump(exclude_none=True, exclude={"actor"})
    if "evidence_ids" in changes:
        valid_evidence = set(
            session.scalars(select(models.Evidence.id).where(models.Evidence.investigation_id == investigation_id))
        )
        invalid = set(changes["evidence_ids"]) - valid_evidence
        if invalid:
            raise HTTPException(422, f"Evidence does not belong to investigation: {', '.join(sorted(invalid))}")
    for field, value in changes.items():
        setattr(hypothesis, field, value)
    _audit(
        session,
        investigation_id,
        "HYPOTHESIS_UPDATED",
        request.actor,
        f"Updated hypothesis {hypothesis_id}",
        {"hypothesis_id": hypothesis_id, "changed_fields": sorted(changes)},
    )
    session.commit()
    return {"hypothesis_id": hypothesis.id, "investigation": get_investigation(session, investigation_id)}


def set_verdict(session: Session, investigation_id: str, verdict: str, actor: str) -> dict[str, Any]:
    investigation = session.get(models.Investigation, investigation_id)
    if not investigation:
        raise HTTPException(404, f"Investigation {investigation_id} not found")
    _require_open_investigation(investigation)
    investigation.verdict = verdict
    investigation.status = "CLOSED" if verdict != "INCONCLUSIVE" else "OPEN"
    investigation.finding.status = (
        "ESCALATED" if verdict == "INCIDENT" else "INVESTIGATING" if verdict == "INCONCLUSIVE" else "CLOSED"
    )
    _audit(session, investigation_id, "VERDICT_CHANGED", actor, f"Human set verdict to {verdict}")
    if verdict == "INCIDENT":
        incident = session.scalar(select(models.Incident).where(models.Incident.investigation_id == investigation_id))
        if not incident:
            incident = models.Incident(
                id=_next_id(session, models.Incident, "INC"),
                investigation_id=investigation_id,
                title=f"Incident from {investigation.finding_id}",
                severity=investigation.finding.severity,
            )
            session.add(incident)
            session.flush()
            _audit(
                session,
                investigation_id,
                "INCIDENT_CREATED",
                actor,
                f"Created incident {incident.id}",
                {"incident_id": incident.id},
            )
    session.commit()
    return get_investigation(session, investigation_id)
