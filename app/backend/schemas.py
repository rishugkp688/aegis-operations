from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Actor = Literal["human", "agent", "system"]


class SearchEventsRequest(BaseModel):
    query: str | None = Field(default=None, max_length=160)
    host: str | None = Field(default=None, max_length=160)
    user: str | None = Field(default=None, max_length=160)
    process: str | None = Field(default=None, max_length=260)
    event_type: str | None = Field(default=None, max_length=80)
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=1_000_000)


class EventContextRequest(BaseModel):
    before: int = Field(default=3, ge=0, le=20)
    after: int = Field(default=3, ge=0, le=20)


class AggregateRequest(BaseModel):
    group_by: Literal["host", "user", "process", "event_type"]
    host: str | None = Field(default=None, max_length=160)
    user: str | None = Field(default=None, max_length=160)
    minutes: int = Field(default=60, ge=1, le=1440)
    limit: int = Field(default=10, ge=1, le=25)


class StartInvestigationRequest(BaseModel):
    actor: Actor = "human"


class AddEvidenceRequest(BaseModel):
    event_ids: list[str] = Field(min_length=1, max_length=10)
    rationale: str = Field(min_length=3, max_length=600)
    actor: Actor = "human"

    @field_validator("event_ids")
    @classmethod
    def unique_event_ids(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class CreateHypothesisRequest(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    reasoning: str = Field(min_length=3, max_length=1200)
    confidence: int = Field(default=50, ge=0, le=100)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    actor: Actor = "human"


class UpdateHypothesisRequest(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=180)
    reasoning: str | None = Field(default=None, min_length=3, max_length=1200)
    status: Literal["OPEN", "SUPPORTED", "REFUTED"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    evidence_ids: list[str] | None = Field(default=None, max_length=20)
    actor: Actor = "human"


class VerdictRequest(BaseModel):
    verdict: Literal["BENIGN", "SUSPICIOUS", "INCIDENT", "INCONCLUSIVE"]
    actor: Literal["human"] = "human"


class ResetWorkspaceRequest(BaseModel):
    confirmation: Literal["RESET"]


class RuleStateRequest(BaseModel):
    enabled: bool


class ModelSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
