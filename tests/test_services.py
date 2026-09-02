from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError


database_file = tempfile.NamedTemporaryFile(prefix="soc-workspace-test-", suffix=".db", delete=False)
database_file.close()
os.environ["DATABASE_URL"] = f"sqlite:///{database_file.name}"

from app.backend.database import SessionLocal, create_schema, engine  # noqa: E402
from app.backend.schemas import (  # noqa: E402
    AddEvidenceRequest,
    CreateHypothesisRequest,
    ResetWorkspaceRequest,
    SearchEventsRequest,
    VerdictRequest,
)
from app.backend.services import (  # noqa: E402
    add_evidence,
    create_hypothesis,
    ingest_dataset,
    list_datasets,
    list_findings,
    list_sigma_rules,
    reset_workspace,
    search_events,
    set_sigma_rule_state,
    start_investigation,
    set_verdict,
    workspace_status,
)


@pytest.fixture(scope="module")
def session():
    create_schema()
    with SessionLocal() as database_session:
        yield database_session
    engine.dispose()
    Path(database_file.name).unlink(missing_ok=True)


def test_empty_workspace_has_only_open_source_catalog(session) -> None:
    workspace = workspace_status(session)
    assert workspace["ingested"] is False
    assert workspace["counts"]["normalized_events"] == 0
    assert workspace["detection_engine"]["available_rules"] == 30
    datasets = list_datasets(session)
    assert len(datasets) == 3
    assert sum(item["available_events"] for item in datasets) == 11_435
    assert {item["provider"] for item in datasets} == {"Splunk Attack Data"}
    assert all(item["license"] == "Apache-2.0" for item in datasets)


def test_sigma_rule_catalog_compiles_without_ingestion(session) -> None:
    rules = list_sigma_rules(session)
    assert len(rules) == 30
    assert all(rule["backend"] == "pySigma SQLite 1.x" for rule in rules)
    assert all(rule["mitre_techniques"] for rule in rules)
    assert all(rule["author"] for rule in rules)
    assert all(rule["compatibility"] == "compatible" for rule in rules)
    assert all(rule["enabled"] for rule in rules)


def test_encoded_powershell_ingestion_is_real_and_idempotent(session) -> None:
    first = ingest_dataset(session, "splunk-t1059-001")
    assert first["accepted"] == 1185
    assert first["rejected"] == 0
    assert first["detection_run"]["rules_evaluated"] == 30
    assert first["detection_run"]["triage_groups"] == 1
    assert first["detection_run"]["errors"] == []
    assert first["already_ingested"] is False

    encoded = next(
        finding
        for finding in list_findings(session)
        if finding["rule_id"] == "fb843269-508c-4b76-8b8d-88679db22ce7"
    )
    assert encoded["matched_event_count"] == 1
    assert encoded["signal_count"] == 3
    assert encoded["rule_count"] == 3
    assert encoded["event_ids"] == ["PSE-001031"]
    assert encoded["sigma"]["techniques"] == ["T1059.001"]

    second = ingest_dataset(session, "splunk-t1059-001")
    assert second["already_ingested"] is True
    assert second["accepted"] == 0
    assert second["counts"] == first["counts"]


def test_searches_normalized_open_source_telemetry(session) -> None:
    result = search_events(session, SearchEventsRequest(query="Exec bypass -enc", limit=10))
    assert result["total"] == 1
    assert result["items"][0]["id"] == "PSE-001031"
    assert result["items"][0]["source"] == "splunk_attack_data_t1059_001"


def test_all_sources_expand_sigma_coverage_without_duplicate_findings(session) -> None:
    lsass = ingest_dataset(session, "splunk-t1003-001")
    transfer = ingest_dataset(session, "splunk-t1105")
    assert lsass["accepted"] == 7960
    assert transfer["accepted"] == 2290
    assert lsass["detection_run"]["errors"] == []
    assert transfer["detection_run"]["errors"] == []

    workspace = workspace_status(session)
    assert workspace["counts"]["raw_logs"] == 11_435
    assert workspace["counts"]["normalized_events"] == 11_435
    assert workspace["counts"]["rules"] == 30
    assert workspace["counts"]["findings"] == 22
    assert workspace["detection_engine"]["matched_rules"] == 29
    assert workspace["detection_engine"]["signal_count"] == 276
    assert workspace["detection_engine"]["distinct_detected_events"] == 133
    assert workspace["detection_engine"]["suppressed_duplicates"] == 143

    final_page = search_events(session, SearchEventsRequest(limit=50, offset=11_400))
    assert final_page["total"] == 11_435
    assert len(final_page["items"]) == 35

    findings = list_findings(session)
    assert all(finding["risk_score"] > 0 for finding in findings)
    assert any(finding["rule_count"] > 1 for finding in findings)
    assert {finding["engine"] for finding in findings} == {"sigma"}
    procdump = next(rule for rule in list_sigma_rules(session) if rule["id"] == "5afee48e-67dd-4e03-a783-f74259dcf998")
    assert procdump["match_count"] == 8
    procdump_finding = next(
        finding for finding in findings if finding["rule_id"] == "5afee48e-67dd-4e03-a783-f74259dcf998"
    )
    assert "Florian Roth" in procdump_finding["sigma"]["author"]
    assert "SELECT * FROM sigma_events" in procdump_finding["sigma"]["compiled_query"]


def test_shared_investigation_state_and_guardrails(session) -> None:
    encoded = next(
        finding
        for finding in list_findings(session)
        if finding["rule_id"] == "fb843269-508c-4b76-8b8d-88679db22ce7"
    )
    investigation = start_investigation(session, encoded["id"], "human")
    investigation_id = investigation["id"]

    evidence_response = add_evidence(
        session,
        investigation_id,
        AddEvidenceRequest(
            event_ids=encoded["event_ids"],
            rationale="Encoded PowerShell execution matched by the attributed Sigma rule.",
            actor="agent",
        ),
    )
    evidence_ids = evidence_response["created_evidence_ids"]
    assert len(evidence_ids) == 1

    hypothesis_response = create_hypothesis(
        session,
        investigation_id,
        CreateHypothesisRequest(
            title="Encoded PowerShell execution",
            reasoning="The exact command line satisfies the Sigma content selection.",
            confidence=92,
            evidence_ids=evidence_ids,
            actor="agent",
        ),
    )
    context = hypothesis_response["investigation"]
    assert context["hypotheses"][0]["created_by"] == "agent"
    assert any(item["actor"] == "agent" for item in context["timeline"])

    with pytest.raises(HTTPException) as error:
        add_evidence(
            session,
            investigation_id,
            AddEvidenceRequest(event_ids=["PSE-999999"], rationale="Invented evidence", actor="agent"),
        )
    assert error.value.status_code == 422

    with pytest.raises(ValidationError):
        VerdictRequest.model_validate({"verdict": "BENIGN", "actor": "agent"})

    closed = set_verdict(session, investigation_id, "INCIDENT", "human")
    assert closed["status"] == "CLOSED"
    assert closed["finding"]["status"] == "ESCALATED"
    assert any(item["event_type"] == "INCIDENT_CREATED" for item in closed["timeline"])
    closed_counts = workspace_status(session)["counts"]
    assert closed_counts["open_investigations"] == 0
    assert closed_counts["open_findings"] == 21

    with pytest.raises(HTTPException) as closed_error:
        add_evidence(
            session,
            investigation_id,
            AddEvidenceRequest(
                event_ids=encoded["event_ids"],
                rationale="A closed case must reject additional evidence.",
                actor="human",
            ),
        )
    assert closed_error.value.status_code == 409

    with pytest.raises(HTTPException) as verdict_error:
        set_verdict(session, investigation_id, "BENIGN", "human")
    assert verdict_error.value.status_code == 409

    another = next(finding for finding in list_findings(session) if finding["id"] != encoded["id"])
    retained = start_investigation(session, another["id"], "human")
    inconclusive = set_verdict(session, retained["id"], "INCONCLUSIVE", "human")
    assert inconclusive["status"] == "OPEN"
    assert inconclusive["finding"]["status"] == "INVESTIGATING"
    assert workspace_status(session)["counts"]["open_investigations"] == 1


def test_rule_state_is_persistent_and_reruns_detection(session) -> None:
    rule_id = "a18dd26b-6450-46de-8c91-9659150cf088"
    before = workspace_status(session)
    response = set_sigma_rule_state(session, rule_id, False)
    assert response["rule"]["enabled"] is False
    assert response["workspace"]["detection_engine"]["enabled_rules"] == 29
    assert response["workspace"]["detection_engine"]["signal_count"] == before["detection_engine"]["signal_count"]

    restored = set_sigma_rule_state(session, rule_id, True)
    assert restored["rule"]["enabled"] is True
    assert restored["workspace"]["detection_engine"]["enabled_rules"] == 30


def test_reset_is_confirmed_complete_and_restartable(session) -> None:
    with pytest.raises(ValidationError):
        ResetWorkspaceRequest.model_validate({"confirmation": "yes"})

    response = reset_workspace(session)
    assert response["reset"] is True
    assert response["removed"]["raw_logs"] == 11_435
    assert all(value == 0 for value in response["workspace"]["counts"].values())
    assert all(not dataset["ingested"] for dataset in response["workspace"]["datasets"])

    restarted = ingest_dataset(session, "splunk-t1003-001")
    assert restarted["accepted"] == 7960
    assert restarted["counts"]["normalized_events"] == 7960
    powershell_second = ingest_dataset(session, "splunk-t1059-001")
    assert powershell_second["accepted"] == 1185
    assert powershell_second["counts"]["normalized_events"] == 9145
    assert powershell_second["detection_run"]["errors"] == []


def test_unknown_dataset_is_rejected(session) -> None:
    with pytest.raises(HTTPException) as error:
        ingest_dataset(session, "made-up-source")
    assert error.value.status_code == 404
