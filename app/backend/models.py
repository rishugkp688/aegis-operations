from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RawLog(Base):
    __tablename__ = "raw_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_record_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    raw_text: Mapped[str] = mapped_column(Text)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow)
    normalized_event: Mapped["NormalizedEvent"] = relationship(back_populates="raw_log")


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(index=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    host: Mapped[str | None] = mapped_column(String(160), index=True)
    user: Mapped[str | None] = mapped_column(String(160), index=True)
    process: Mapped[str | None] = mapped_column(String(260), index=True)
    parent_process: Mapped[str | None] = mapped_column(String(260))
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    command_line: Mapped[str | None] = mapped_column(Text)
    additional_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_log_id: Mapped[int] = mapped_column(ForeignKey("raw_logs.id"), unique=True)
    raw_log: Mapped[RawLog] = relationship(back_populates="normalized_event")


class SigmaEvent(Base):
    """Wide, case-preserving projection used by generated Sigma SQL queries."""

    __tablename__ = "sigma_events"

    event_id: Mapped[str] = mapped_column(ForeignKey("normalized_events.id"), primary_key=True)
    EventID: Mapped[int] = mapped_column(index=True)
    Channel: Mapped[str | None] = mapped_column(String(180), index=True)
    Computer: Mapped[str | None] = mapped_column(String(160), index=True)
    UtcTime: Mapped[str | None] = mapped_column(String(40))
    Image: Mapped[str | None] = mapped_column(Text)
    CommandLine: Mapped[str | None] = mapped_column(Text)
    ParentImage: Mapped[str | None] = mapped_column(Text)
    User: Mapped[str | None] = mapped_column(String(180))
    SourceImage: Mapped[str | None] = mapped_column(Text)
    TargetImage: Mapped[str | None] = mapped_column(Text)
    GrantedAccess: Mapped[str | None] = mapped_column(String(40))
    CallTrace: Mapped[str | None] = mapped_column(Text)
    TargetFilename: Mapped[str | None] = mapped_column(Text)
    DestinationIp: Mapped[str | None] = mapped_column(String(64))
    DestinationPort: Mapped[str | None] = mapped_column(String(16))
    QueryName: Mapped[str | None] = mapped_column(Text)
    Hashes: Mapped[str | None] = mapped_column(Text)
    IntegrityLevel: Mapped[str | None] = mapped_column(String(60))
    OriginalFileName: Mapped[str | None] = mapped_column(Text)
    ParentCommandLine: Mapped[str | None] = mapped_column(Text)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(180))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    description: Mapped[str] = mapped_column(Text)
    mitre_technique: Mapped[str | None] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(default=True)
    sigma_artifact: Mapped["SigmaRuleArtifact | None"] = relationship(back_populates="rule")


class SigmaRuleArtifact(Base):
    __tablename__ = "sigma_rule_artifacts"

    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(30))
    author: Mapped[str] = mapped_column(Text)
    license: Mapped[str] = mapped_column(String(80), default="Detection Rule License 1.1")
    source_url: Mapped[str] = mapped_column(Text)
    yaml_text: Mapped[str] = mapped_column(Text)
    compiled_query: Mapped[str] = mapped_column(Text)
    backend: Mapped[str] = mapped_column(String(80), default="pySigma SQLite")
    pipeline: Mapped[str] = mapped_column(String(80), default="Sysmon")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    compatibility: Mapped[str] = mapped_column(String(30), default="compatible", index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    rule: Mapped[Rule] = relationship(back_populates="sigma_artifact")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), index=True)
    title: Mapped[str] = mapped_column(String(220))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    description: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(index=True)
    status: Mapped[str] = mapped_column(String(30), default="NEW")
    entities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_key: Mapped[str | None] = mapped_column(String(160), unique=True, index=True)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(default=0, index=True)
    confidence: Mapped[int] = mapped_column(default=0)
    first_seen: Mapped[datetime | None] = mapped_column(index=True)
    last_seen: Mapped[datetime | None] = mapped_column(index=True)
    signal_count: Mapped[int] = mapped_column(default=0)
    suppressed_signal_count: Mapped[int] = mapped_column(default=0)
    rule: Mapped[Rule] = relationship()
    event_links: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    signals: Mapped[list["DetectionSignal"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingEvent(Base):
    __tablename__ = "finding_events"
    __table_args__ = (UniqueConstraint("finding_id", "event_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("normalized_events.id"), index=True)
    finding: Mapped[Finding] = relationship(back_populates="event_links")
    event: Mapped[NormalizedEvent] = relationship()


class DetectionSignal(Base):
    __tablename__ = "detection_signals"
    __table_args__ = (UniqueConstraint("rule_id", "event_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("normalized_events.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    finding: Mapped[Finding] = relationship(back_populates="signals")
    rule: Mapped[Rule] = relationship()
    event: Mapped[NormalizedEvent] = relationship()


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), unique=True)
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    verdict: Mapped[str | None] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    finding: Mapped[Finding] = relationship()
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    hypotheses: Mapped[list["Hypothesis"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    events: Mapped[list["InvestigationEvent"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("investigation_id", "event_id"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("normalized_events.id"), index=True)
    rationale: Mapped[str] = mapped_column(Text)
    added_by: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="evidence")
    event: Mapped[NormalizedEvent] = relationship()


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    title: Mapped[str] = mapped_column(String(220))
    reasoning: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    confidence: Mapped[int] = mapped_column(default=50)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="hypotheses")


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    actor: Mapped[str] = mapped_column(String(30))
    summary: Mapped[str] = mapped_column(String(500))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    investigation: Mapped[Investigation] = relationship(back_populates="events")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), unique=True)
    title: Mapped[str] = mapped_column(String(220))
    severity: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
