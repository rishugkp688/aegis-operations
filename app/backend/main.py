from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import create_schema, get_db
from .schemas import (
    AddEvidenceRequest,
    AggregateRequest,
    CreateHypothesisRequest,
    EventContextRequest,
    SearchEventsRequest,
    ResetWorkspaceRequest,
    RuleStateRequest,
    StartInvestigationRequest,
    UpdateHypothesisRequest,
    VerdictRequest,
)
from .services import (
    add_evidence,
    aggregate_activity,
    create_hypothesis,
    get_event,
    get_event_context,
    get_finding,
    get_investigation,
    ingest_dataset,
    list_datasets,
    list_findings,
    list_investigations,
    list_sigma_rules,
    reset_workspace,
    search_events,
    set_verdict,
    set_sigma_rule_state,
    start_investigation,
    update_hypothesis,
    workspace_status,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_schema()
    yield


app = FastAPI(
    title="aegis-operations",
    version="0.1.0",
    lifespan=lifespan,
)

development_origins = "http://localhost:5173,http://127.0.0.1:5173"
allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", development_origins).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def webmcp_document_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Origin-Agent-Cluster"] = "?1"
    response.headers["Permissions-Policy"] = "tools=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/api/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/api/workspace")
def get_workspace(db: Session = Depends(get_db)) -> dict[str, Any]:
    return workspace_status(db)


@app.get("/api/datasets")
def datasets(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_datasets(db)


@app.post("/api/datasets/{dataset_id}/ingest")
def ingest_open_dataset(dataset_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return ingest_dataset(db, dataset_id)


@app.get("/api/rules")
def rules(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_sigma_rules(db)


@app.patch("/api/rules/{rule_id}")
def update_rule_state(
    rule_id: str,
    request: RuleStateRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return set_sigma_rule_state(db, rule_id, request.enabled)


@app.post("/api/workspace/reset")
def reset(request: ResetWorkspaceRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return reset_workspace(db)


@app.get("/api/events")
def events(
    query: str | None = Query(default=None, max_length=160),
    host: str | None = Query(default=None, max_length=160),
    user: str | None = Query(default=None, max_length=160),
    process: str | None = Query(default=None, max_length=260),
    event_type: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return search_events(
        db,
        SearchEventsRequest(
            query=query,
            host=host,
            user=user,
            process=process,
            event_type=event_type,
            limit=limit,
            offset=offset,
        ),
    )


@app.get("/api/events/{event_id}")
def event_detail(event_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return get_event(db, event_id)


@app.post("/api/events/{event_id}/context")
def event_context(
    event_id: str,
    request: EventContextRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return get_event_context(db, event_id, request.before, request.after)


@app.post("/api/events/aggregate")
def aggregate(request: AggregateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return aggregate_activity(db, request)


@app.get("/api/findings")
def findings(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_findings(db)


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return get_finding(db, finding_id)


@app.post("/api/findings/{finding_id}/investigations")
def create_investigation(
    finding_id: str,
    request: StartInvestigationRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return start_investigation(db, finding_id, request.actor)


@app.get("/api/investigations")
def investigations(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_investigations(db)


@app.get("/api/investigations/{investigation_id}")
def investigation_detail(investigation_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return get_investigation(db, investigation_id)


@app.post("/api/investigations/{investigation_id}/evidence")
def pin_evidence(
    investigation_id: str,
    request: AddEvidenceRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return add_evidence(db, investigation_id, request)


@app.post("/api/investigations/{investigation_id}/hypotheses")
def new_hypothesis(
    investigation_id: str,
    request: CreateHypothesisRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return create_hypothesis(db, investigation_id, request)


@app.patch("/api/investigations/{investigation_id}/hypotheses/{hypothesis_id}")
def revise_hypothesis(
    investigation_id: str,
    hypothesis_id: str,
    request: UpdateHypothesisRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return update_hypothesis(db, investigation_id, hypothesis_id, request)


@app.post("/api/investigations/{investigation_id}/verdict")
def verdict(
    investigation_id: str,
    request: VerdictRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return set_verdict(db, investigation_id, request.verdict, request.actor)


FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if FRONTEND_DIST.exists():
    assets = FRONTEND_DIST / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend(full_path: str) -> FileResponse:
        requested = FRONTEND_DIST / full_path
        if full_path and requested.is_file():
            return FileResponse(requested)
        return FileResponse(FRONTEND_DIST / "index.html")
