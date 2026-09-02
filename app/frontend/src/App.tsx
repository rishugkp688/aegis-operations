import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { api } from "./api";
import type { Finding, Investigation, SecurityEvent, SigmaRule, Workspace } from "./types";
import { registerWebMcpTools } from "./webmcp";
import type { WebMcpAvailability } from "./webmcp";

type View = "overview" | "logs" | "detections" | "findings" | "investigation";
type Theme = "dark" | "light";

const viewLabels: Record<View, string> = {
  overview: "Overview",
  findings: "Alerts",
  investigation: "Investigations",
  logs: "Event search",
  detections: "Detection rules",
};

const emptyWorkspace: Workspace = {
  application: "WebMCP Security Investigation Workspace",
  dataset: "Splunk Attack Data detection lab",
  ingested: false,
  counts: { raw_logs: 0, normalized_events: 0, rules: 0, findings: 0, open_findings: 0, investigations: 0, open_investigations: 0 },
  webmcp_tools: 8,
  datasets: [],
  detection_engine: { name: "pySigma", backend: "SQLite", pipeline: "Sysmon", official_rules: 0, available_rules: 30, enabled_rules: 30, matched_rules: 0, signal_count: 0, distinct_detected_events: 0, suppressed_duplicates: 0 },
};

const DEFAULT_EVENT_PAGE_SIZE = 50;

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem("aegis-theme");
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    // Storage can be unavailable in hardened or ephemeral browser contexts.
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

const basename = (path: string | null) => path?.split("\\").pop() ?? "—";
const time = (value: string) =>
  new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(
    new Date(value),
  );
const dateTime = (value: string) =>
  new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));

function Severity({ value }: { value: Finding["severity"] }) {
  return <span className={`severity severity-${value}`}><i />{value}</span>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><div className="empty-mark">◇</div><strong>{title}</strong><p>{detail}</p></div>;
}

function PageGuide({ title, detail, steps, action }: {
  title: string;
  detail: string;
  steps: string[];
  action?: { label: string; onClick: () => void };
}) {
  return <aside className="page-guide" aria-label="Page guidance"><div className="guide-mark">?</div><div><strong>{title}</strong><p>{detail}</p><ol>{steps.map((step) => <li key={step}>{step}</li>)}</ol></div>{action && <button className="guide-action" onClick={action.onClick}>{action.label} →</button>}</aside>;
}

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [workspace, setWorkspace] = useState<Workspace>(emptyWorkspace);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [eventOffset, setEventOffset] = useState(0);
  const [eventPageSize, setEventPageSize] = useState(DEFAULT_EVENT_PAGE_SIZE);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [search, setSearch] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [webMcp, setWebMcp] = useState<WebMcpAvailability>({ available: false, count: 0, detail: "Checking browser capability…", surface: null });
  const [resetOpen, setResetOpen] = useState(false);
  const [resetText, setResetText] = useState("");
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const activeInvestigationId = useRef<string | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f3f5f8" : "#080b11");
    try { localStorage.setItem("aegis-theme", theme); } catch { /* Keep the in-memory preference. */ }
  }, [theme]);

  useEffect(() => {
    activeInvestigationId.current = activeInvestigation?.status === "OPEN" ? activeInvestigation.id : null;
  }, [activeInvestigation]);

  const loadEventPage = useCallback(async (query: string, offset: number, limit: number) => {
    try {
      const result = await api.events({ query, limit, offset });
      setEvents(result.items);
      setEventTotal(result.total);
      setEventOffset(offset);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load telemetry");
    }
  }, []);

  const loadAll = useCallback(async () => {
    try {
      const [workspaceData, findingData, investigationData, ruleData] = await Promise.all([
        api.workspace(),
        api.findings(),
        api.investigations(),
        api.rules(),
      ]);
      setWorkspace(workspaceData);
      setFindings(findingData);
      setInvestigations(investigationData);
      setRules(ruleData);
      setError(null);
      const openInvestigations = investigationData.filter((item) => item.status === "OPEN");
      if (activeInvestigationId.current) {
        const current = investigationData.find((item) => item.id === activeInvestigationId.current);
        if (current?.status === "OPEN") setActiveInvestigation(current);
        else {
          activeInvestigationId.current = openInvestigations[0]?.id ?? null;
          setActiveInvestigation(openInvestigations[0] ?? null);
        }
      } else {
        activeInvestigationId.current = openInvestigations[0]?.id ?? null;
        setActiveInvestigation(openInvestigations[0] ?? null);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load workspace");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void Promise.all([loadAll(), loadEventPage("", 0, DEFAULT_EVENT_PAGE_SIZE)]); }, [loadAll, loadEventPage]);

  useEffect(() => {
    let disposed = false;
    let unregister: (() => void) | undefined;
    void registerWebMcpTools(
      () => activeInvestigationId.current,
      (status) => { if (!disposed) setWebMcp(status); },
    ).then((cleanup) => {
      if (disposed) cleanup();
      else unregister = cleanup;
    });
    return () => { disposed = true; unregister?.(); };
  }, []);

  useEffect(() => {
    const refresh = () => void loadAll();
    window.addEventListener("webmcp:mutation", refresh);
    return () => window.removeEventListener("webmcp:mutation", refresh);
  }, [loadAll]);

  const ingest = async (datasetId = "splunk-t1003-001") => {
    setBusy(true);
    setError(null);
    try {
      await api.ingest(datasetId);
      setSearch("");
      setAppliedSearch("");
      setEventPageSize(DEFAULT_EVENT_PAGE_SIZE);
      await Promise.all([loadAll(), loadEventPage("", 0, DEFAULT_EVENT_PAGE_SIZE)]);
      setView("findings");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ingestion failed");
    } finally {
      setBusy(false);
    }
  };

  const runSearch = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    try {
      setAppliedSearch(search);
      await loadEventPage(search, 0, eventPageSize);
    } finally {
      setBusy(false);
    }
  };

  const applySearch = async (value: string) => {
    setSearch(value);
    setAppliedSearch(value);
    setBusy(true);
    try {
      await loadEventPage(value, 0, eventPageSize);
    } finally {
      setBusy(false);
    }
  };

  const changeEventPage = async (offset: number) => {
    setBusy(true);
    try {
      await loadEventPage(appliedSearch, offset, eventPageSize);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } finally {
      setBusy(false);
    }
  };

  const changeEventPageSize = async (size: number) => {
    setBusy(true);
    setEventPageSize(size);
    try {
      await loadEventPage(appliedSearch, 0, size);
    } finally {
      setBusy(false);
    }
  };

  const inspectEvent = async (eventId: string) => {
    setSelectedEvent(await api.event(eventId));
  };

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await api.setRuleEnabled(ruleId, enabled);
      await loadAll();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to update detection content");
    } finally {
      setBusy(false);
    }
  };

  const openInvestigation = async (findingId: string) => {
    setBusy(true);
    try {
      const investigation = await api.startInvestigation(findingId);
      activeInvestigationId.current = investigation.status === "OPEN" ? investigation.id : null;
      setActiveInvestigation(investigation);
      if (investigation.status === "OPEN") await loadAll();
      setView("investigation");
    } finally {
      setBusy(false);
    }
  };

  const selectInvestigation = (investigation: Investigation) => {
    activeInvestigationId.current = investigation.status === "OPEN" ? investigation.id : null;
    setActiveInvestigation(investigation);
    setView("investigation");
  };

  const closeInvestigation = () => {
    activeInvestigationId.current = null;
    setActiveInvestigation(null);
    setSelectedEvent(null);
    setView("investigation");
  };

  const resetWorkspace = async () => {
    if (resetText !== "RESET") return;
    setBusy(true);
    setError(null);
    try {
      await api.reset();
      activeInvestigationId.current = null;
      setActiveInvestigation(null);
      setSelectedEvent(null);
      setSearch("");
      setAppliedSearch("");
      setEventPageSize(DEFAULT_EVENT_PAGE_SIZE);
      setResetOpen(false);
      setResetText("");
      setView("overview");
      await Promise.all([loadAll(), loadEventPage("", 0, DEFAULT_EVENT_PAGE_SIZE)]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Workspace reset failed");
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return <div className="boot"><div className="boot-logo">SOC</div><span>Loading investigation workspace…</span></div>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span><div><strong>Aegis Operations</strong><small>HUMAN + AGENT SOC</small></div></div>
        <nav>
          <label>INVESTIGATION WORKFLOW</label>
          {([ ["overview", "1", "Overview"], ["findings", "2", "Alerts"], ["investigation", "3", "Investigations"] ] as [View, string, string][]).map(([key, icon, label]) => <button title={label} key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}><span>{icon}</span>{label}{key === "findings" && workspace.counts.open_findings > 0 && <em>{workspace.counts.open_findings}</em>}</button>)}
          <label>INVESTIGATION TOOLS</label>
          {([ ["logs", "⌕", "Event search"], ["detections", "Σ", "Detection rules"] ] as [View, string, string][]).map(([key, icon, label]) => <button title={label} key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}><span>{icon}</span>{label}</button>)}
        </nav>
        <div className="sidebar-foot">
          <div className={`agent-state ${webMcp.available ? "online" : ""}`}><i />
            <div><strong>{webMcp.available ? "Agent collaboration ready" : "Agent tools unavailable"}</strong><small title={webMcp.detail}>{webMcp.available ? `${webMcp.count} WebMCP tools connected` : webMcp.detail}</small></div>
          </div>
          <button className="reset-link" onClick={() => setResetOpen(true)}>↺ Reset workspace</button>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div><span className="eyebrow">AEGIS /</span><strong>{viewLabels[view]}</strong></div>
          <div className="top-actions"><span className="tenant">DETECTION LAB</span><span className={`sensor ${error ? "degraded" : ""}`}><i /> {error ? "ACTION REQUIRED" : "SYSTEM HEALTHY"}</span><button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>{theme === "dark" ? <svg className="theme-icon" aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41" /></svg> : <svg className="theme-icon" aria-hidden="true" viewBox="0 0 24 24"><path d="M20.2 15.1A8.5 8.5 0 0 1 8.9 3.8a8.5 8.5 0 1 0 11.3 11.3Z" /></svg>}<span className="theme-label">{theme === "dark" ? "Light" : "Dark"}</span></button><span className="avatar" title="Local analyst">RA</span></div>
        </header>

        {error && <div className="error-banner"><span>!</span>{error}<button onClick={() => setError(null)}>×</button></div>}

        <section className="content">
          {view === "overview" && (
            <Overview workspace={workspace} busy={busy} ingest={ingest} findings={findings} onOpenFinding={openInvestigation} navigate={setView} />
          )}
          {view === "logs" && (
            <Logs
              events={events}
              total={eventTotal}
              search={search}
              appliedSearch={appliedSearch}
              setSearch={setSearch}
              runSearch={runSearch}
              applySearch={applySearch}
              inspectEvent={inspectEvent}
              offset={eventOffset}
              pageSize={eventPageSize}
              changePage={changeEventPage}
              changePageSize={changeEventPageSize}
              busy={busy}
              hasActiveInvestigation={Boolean(activeInvestigation)}
            />
          )}
          {view === "findings" && (
            <Findings findings={findings} openInvestigation={openInvestigation} busy={busy} />
          )}
          {view === "detections" && <DetectionContent rules={rules} busy={busy} toggleRule={toggleRule} />}
          {view === "investigation" && (
            <InvestigationWorkspace
              investigation={activeInvestigation}
              investigations={investigations}
              selectInvestigation={selectInvestigation}
              closeInvestigation={closeInvestigation}
              refresh={loadAll}
              inspectEvent={inspectEvent}
              webMcp={webMcp}
              navigate={setView}
            />
          )}
        </section>
      </main>

      {selectedEvent && (
        <EventDrawer
          event={selectedEvent}
          investigation={activeInvestigation}
          close={() => setSelectedEvent(null)}
          changed={async () => { await loadAll(); setSelectedEvent(null); }}
        />
      )}
      {resetOpen && <ResetDialog value={resetText} setValue={setResetText} busy={busy} cancel={() => { setResetOpen(false); setResetText(""); }} confirm={resetWorkspace} />}
    </div>
  );
}

function Overview({
  workspace,
  busy,
  ingest,
  findings,
  onOpenFinding,
  navigate,
}: {
  workspace: Workspace;
  busy: boolean;
  ingest: (datasetId?: string) => void;
  findings: Finding[];
  onOpenFinding: (id: string) => void;
  navigate: (view: View) => void;
}) {
  const signalCount = workspace.detection_engine.signal_count;
  const activeSources = workspace.datasets.filter((item) => item.ingested).length;
  const stats = [
    { section: "TELEMETRY", status: `${activeSources} OF ${workspace.datasets.length} SOURCES ONLINE`, label: "Telemetry events", value: workspace.counts.normalized_events, caption: "INGESTED + NORMALIZED" },
    { section: "DETECTION", status: `${workspace.detection_engine.name} / ${workspace.detection_engine.backend}`, label: "Rule matches", value: signalCount, caption: `${workspace.detection_engine.matched_rules} OF ${workspace.detection_engine.available_rules} RULES MATCHED` },
    { section: "CORRELATION", status: workspace.counts.open_findings ? `${workspace.counts.open_findings} OPEN · ${workspace.counts.findings} TOTAL` : "QUEUE CLEAR", label: "Open alerts", value: workspace.counts.open_findings, caption: `${signalCount} RELATED RULE MATCHES GROUPED`, warn: workspace.counts.open_findings > 0 },
    { section: "INVESTIGATION", status: `${workspace.counts.investigations} TOTAL CASES`, label: "Open investigations", value: workspace.counts.open_investigations, caption: "HUMAN + AGENT" },
  ];
  const hasTelemetry = workspace.counts.normalized_events > 0;
  return <>
    <div className="page-heading"><div><span className="eyebrow">START HERE</span><h1>Security operations overview</h1><p>Ingest endpoint events, review correlated alerts, and investigate with a human analyst and browser agent sharing the same case.</p></div><div className="live-clock"><i /> WORKSPACE CURRENT</div></div>
    <PageGuide
      title={hasTelemetry ? "Continue your investigation workflow" : "Set up the detection lab"}
      detail={hasTelemetry ? "Your data is ready. Move from alerts to evidence-backed decisions using the numbered navigation." : "Start by connecting one open-source telemetry source. Aegis will normalize it, evaluate Sigma rules, and create correlated alerts."}
      steps={hasTelemetry ? ["Review prioritized alerts", "Open an investigation", "Collect evidence, test a hypothesis, and record a verdict"] : ["Connect a telemetry source below", "Wait for Sigma detection and correlation", "Open Alerts from step 2 in the navigation"]}
      action={hasTelemetry && workspace.counts.open_findings ? { label: `Review ${workspace.counts.open_findings} open alerts`, onClick: () => navigate("findings") } : undefined}
    />
    <div className="stats-grid">{stats.map((stat) => <article className="stat-card" key={stat.label}><header><span>{stat.section}</span><strong className={stat.warn ? "at-risk" : ""}>{stat.status}</strong></header><div><span>{stat.label}</span><strong>{stat.value.toLocaleString()}</strong><small className={stat.warn ? "warn" : ""}>{stat.caption}</small></div></article>)}</div>
    <div className="overview-grid">
      <section className="panel dataset-panel">
        <div className="panel-head"><div><span className="eyebrow">DATA SOURCES</span><h2>Connect telemetry sources</h2></div><span className="panel-count">{workspace.datasets.filter((item) => item.ingested).length} / {workspace.datasets.length} ACTIVE</span></div>
        <div className="dataset-list">{workspace.datasets.map((dataset) => <article className={!dataset.ingested ? "recommended" : ""} key={dataset.id}>
          <div className="dataset-icon">{dataset.technique.split(".")[0].replace("T", "")}</div><div className="dataset-copy"><header><strong>{dataset.name}</strong><span>OPEN SOURCE</span></header><p>{dataset.provider} · {dataset.provenance}</p><footer><span>{dataset.telemetry}</span><span>{dataset.available_events.toLocaleString()} events</span><span>{dataset.technique}</span><span>{dataset.license}</span></footer></div>
          <button className={dataset.ingested ? "source-ready" : "compact-action"} disabled={busy || dataset.ingested} onClick={() => ingest(dataset.id)}>{dataset.ingested ? `✓ ${dataset.ingested_events.toLocaleString()} ready` : busy ? "Ingesting…" : "Connect source"}</button>
        </article>)}</div>
        <div className="pipeline">{[["EVENTS INGESTED", workspace.counts.raw_logs], ["RULE MATCHES", signalCount], ["ALERTS CREATED", workspace.counts.findings], ["INVESTIGATIONS", workspace.counts.investigations]].map(([name, count], index) => <div className="pipe-step" key={name}><span>{name}</span><strong>{Number(count).toLocaleString()}</strong>{index < 3 && <b>→</b>}</div>)}</div>
      </section>
      <section className="panel">
        <div className="panel-head"><div><span className="eyebrow">PRIORITY QUEUE</span><h2>Highest-priority open alerts</h2></div><span className="panel-count">{findings.filter((finding) => ["NEW", "INVESTIGATING"].includes(finding.status)).length}</span></div>
        <div className="finding-stack">
          {findings.filter((finding) => ["NEW", "INVESTIGATING"].includes(finding.status)).slice(0, 4).map((finding) => <button key={finding.id} onClick={() => onOpenFinding(finding.id)}><Severity value={finding.severity} /><div><strong>{finding.title}</strong><small>{finding.id} · {finding.mitre_technique}</small></div><span>›</span></button>)}
          {!findings.some((finding) => ["NEW", "INVESTIGATING"].includes(finding.status)) && <EmptyState title="Open alert queue is clear" detail="Resolved alerts remain available from the Alerts history filter." />}
        </div>
      </section>
    </div>
  </>;
}

function Logs({ events, total, search, appliedSearch, setSearch, runSearch, applySearch, inspectEvent, offset, pageSize, changePage, changePageSize, busy, hasActiveInvestigation }: {
  events: SecurityEvent[];
  total: number;
  search: string;
  appliedSearch: string;
  setSearch: (value: string) => void;
  runSearch: (event?: FormEvent) => void;
  applySearch: (value: string) => Promise<void>;
  inspectEvent: (id: string) => void;
  offset: number;
  pageSize: number;
  changePage: (offset: number) => Promise<void>;
  changePageSize: (size: number) => Promise<void>;
  busy: boolean;
  hasActiveInvestigation: boolean;
}) {
  const first = total ? offset + 1 : 0;
  const last = Math.min(offset + events.length, total);
  const currentPage = total ? Math.floor(offset / pageSize) + 1 : 1;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  return <>
    <div className="page-heading"><div><span className="eyebrow">INVESTIGATION TOOL</span><h1>Event search</h1><p>Search normalized endpoint events and inspect the original source record.</p></div><div className="record-count"><strong>{total.toLocaleString()}</strong><span>matching events</span></div></div>
    <PageGuide title="Use events to verify an alert" detail={hasActiveInvestigation ? "An investigation is active. Open any event to review its fields and pin it as evidence with your rationale." : "You can explore events now, but start an investigation from Alerts before pinning evidence."} steps={["Search by host, user, process, command line, or IP", "Open a row and compare normalized fields with the raw record", hasActiveInvestigation ? "Explain why it matters and pin it to the active investigation" : "Open an alert, then return here to collect evidence"]} />
    <section className="panel table-panel">
      <form className="query-bar" onSubmit={runSearch}><span>⌕</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search process, command line, host, user, IP…" /><button disabled={busy}>Search</button></form>
      <div className="filter-row">{([ ["", "All telemetry"], ["powershell", "PowerShell"], ["lsass", "Credential access"], ["certutil", "Tool transfer"] ] as const).map(([value, label]) => <button type="button" key={label} className={`filter ${appliedSearch === value ? "active" : ""}`} disabled={busy} onClick={() => void applySearch(value)}>{label}</button>)}<span>{first.toLocaleString()}–{last.toLocaleString()} of {total.toLocaleString()}</span><div className="page-shortcuts"><button aria-label="Previous event page" disabled={busy || offset === 0} onClick={() => void changePage(Math.max(0, offset - pageSize))}>‹</button><b>{currentPage} / {pageCount.toLocaleString()}</b><button aria-label="Next event page" disabled={busy || last >= total} onClick={() => void changePage(offset + pageSize)}>›</button></div></div>
      <div className="table-wrap"><table className="events-table"><thead><tr><th>TIME</th><th>EVENT</th><th>HOST</th><th>USER</th><th>PROCESS</th><th>COMMAND / DESTINATION</th><th /></tr></thead><tbody>
        {events.map((event) => { const user = event.user?.replace("CORP\\", "") ?? "—"; const process = basename(event.process); const summary = event.command_line ?? event.destination_ip ?? JSON.stringify(event.additional_fields); return <tr className="event-row" key={event.id} tabIndex={0} onClick={() => inspectEvent(event.id)} onKeyDown={(keyEvent) => { if (keyEvent.key === "Enter" || keyEvent.key === " ") { keyEvent.preventDefault(); inspectEvent(event.id); } }}><td className="mono subtle">{time(event.timestamp)}</td><td><span className="event-id">{event.id}</span><small title={event.event_type}>{event.event_type}</small></td><td><span className="cell-value" title={event.host ?? undefined}>{event.host ?? "—"}</span></td><td><span className="cell-value" title={user}>{user}</span></td><td><span className="cell-value mono" title={process}>{process}</span></td><td><span className="cell-value mono subtle" title={summary}>{summary}</span></td><td><button className="row-action" aria-label={`Inspect event ${event.id}`} onClick={(clickEvent) => { clickEvent.stopPropagation(); inspectEvent(event.id); }}>›</button></td></tr>; })}
      </tbody></table>{!events.length && <EmptyState title="No telemetry" detail="Ingest the dataset or broaden the current search." />}</div>
      <footer className="pagination"><div><span>ROWS PER PAGE</span><select value={pageSize} disabled={busy} onChange={(event) => void changePageSize(Number(event.target.value))}>{[25, 50, 100].map((size) => <option key={size} value={size}>{size}</option>)}</select></div><span>PAGE <strong>{currentPage}</strong> OF <strong>{pageCount.toLocaleString()}</strong></span><nav aria-label="Event pages"><button disabled={busy || offset === 0} onClick={() => void changePage(0)}>First</button><button disabled={busy || offset === 0} onClick={() => void changePage(Math.max(0, offset - pageSize))}>← Previous</button><button disabled={busy || last >= total} onClick={() => void changePage(offset + pageSize)}>Next →</button><button disabled={busy || last >= total} onClick={() => void changePage((pageCount - 1) * pageSize)}>Last</button></nav></footer>
    </section>
  </>;
}

function Findings({ findings, openInvestigation, busy }: { findings: Finding[]; openInvestigation: (id: string) => void; busy: boolean }) {
  const [filter, setFilter] = useState<"open" | "critical" | "high" | "sigma" | "resolved">("open");
  const isOpen = (finding: Finding) => ["NEW", "INVESTIGATING"].includes(finding.status);
  const openFindings = findings.filter(isOpen);
  const filtered = findings.filter((finding) => filter === "resolved" ? !isOpen(finding) : isOpen(finding) && (filter === "open" || (filter === "sigma" ? finding.engine === "sigma" : finding.severity === filter)));
  const signalCount = findings.reduce((total, finding) => total + finding.signal_count, 0);
  const suppressedCount = findings.reduce((total, finding) => total + finding.suppressed_signal_count, 0);
  return <>
    <div className="page-heading"><div><span className="eyebrow">STEP 2 · PRIORITIZE</span><h1>Alerts</h1><p>Review the active queue first; closed and escalated alerts remain available as history.</p></div><div className="record-count"><strong>{openFindings.length}</strong><span>open · {findings.length} total</span></div></div>
    <PageGuide title="Choose what deserves investigation" detail="One alert can contain several rule matches and events. Start with severity and risk, then confirm the affected entity and ATT&CK technique." steps={["Filter and compare alert risk", "Select Investigate to open the shared case", "Review related events before deciding whether the activity is malicious"]} />
    <div className="correlation-note"><span>Σ</span><div><strong>{signalCount} rule matches consolidated into {findings.length} alerts</strong><p>Related matches are grouped by source, host, process, and one-hour window. {suppressedCount} overlaps reuse events already represented in an alert.</p></div></div>
    <section className="panel table-panel"><div className="filter-row">{([ ["open", "Open queue"], ["critical", "Critical"], ["high", "High"], ["sigma", "Sigma"], ["resolved", "Resolved"] ] as const).map(([key, label]) => <button key={key} className={`filter ${filter === key ? "active" : ""}`} onClick={() => setFilter(key)}>{label}</button>)}<span>{filtered.length} shown · newest first</span></div><div className="table-wrap"><table className="findings-table"><thead><tr><th>RISK</th><th>ALERT</th><th>DETECTION SOURCE</th><th>AFFECTED ENTITY</th><th>ATT&CK</th><th>MATCHES</th><th>STATUS</th><th /></tr></thead><tbody>
      {filtered.map((finding) => <tr key={finding.id}><td><Severity value={finding.severity} /><small>{finding.risk_score}/100 risk · {finding.confidence}% confidence</small></td><td><strong>{finding.title}</strong><small>{finding.id} · {dateTime(finding.timestamp)}</small></td><td><span className={`engine-badge ${finding.engine}`}>{finding.engine === "sigma" ? "Σ SIGMA" : "LEGACY"}</span><small>{finding.rule_count} {finding.rule_count === 1 ? "rule" : "rules"} correlated</small></td><td><strong>{finding.entities.hosts?.[0] ?? "—"}</strong><small>{finding.entities.processes?.[0] ? basename(finding.entities.processes[0]) : finding.entities.users?.[0] ?? "—"}</small></td><td><div className="technique-stack">{(finding.sigma?.techniques ?? [finding.mitre_technique]).filter((technique): technique is string => Boolean(technique)).slice(0, 2).map((technique) => <span className="technique" key={technique}>{technique}</span>)}</div></td><td><strong>{finding.signal_count}</strong><small>{finding.matched_event_count} events · {finding.suppressed_signal_count} overlap</small></td><td><span className={`status-text status-${finding.status.toLowerCase()}`}>{finding.status}</span></td><td><button className={isOpen(finding) ? "compact-action" : "archive-action"} disabled={busy} onClick={() => openInvestigation(finding.id)}>{isOpen(finding) ? "Investigate →" : "View record →"}</button></td></tr>)}
    </tbody></table>{!findings.length ? <EmptyState title="Detection queue is empty" detail="Ingest telemetry to run the curated detection rules." /> : !filtered.length && <EmptyState title={filter === "resolved" ? "No resolved alerts" : "No alerts match this queue filter"} detail={filter === "resolved" ? "Conclusive verdicts will move alerts here." : "Try another active-queue filter."} />}</div></section>
  </>;
}

function DetectionContent({ rules, busy, toggleRule }: { rules: SigmaRule[]; busy: boolean; toggleRule: (ruleId: string, enabled: boolean) => Promise<void> }) {
  const producing = rules.filter((rule) => rule.match_count > 0).length;
  const tested = rules.filter((rule) => rule.status === "test").length;
  const stable = rules.filter((rule) => rule.status === "stable").length;
  const healthy = rules.filter((rule) => rule.compatibility === "compatible").length;
  const enabled = rules.filter((rule) => rule.enabled).length;
  return <>
    <div className="page-heading"><div><span className="eyebrow">ADMINISTRATION</span><h1>Detection rules</h1><p>Manage the Sigma analytics that convert endpoint events into rule matches and alerts.</p></div><div className="record-count"><strong>{rules.length}</strong><span>official Sigma rules</span></div></div>
    <PageGuide title="Tune detection coverage carefully" detail="Rules run against all ingested telemetry. Disabling one recalculates matches and can remove alerts, so treat this as an administrative control." steps={["Review rule health and ATT&CK coverage", "Check how many events each rule matches", "Enable or disable rules only when you understand the coverage impact"]} />
    <div className="coverage-grid"><div><span>RULES HEALTHY</span><strong>{healthy} / {rules.length}</strong><small>{enabled} ENABLED · {rules.length - healthy} INCOMPATIBLE</small></div><div><span>RULES WITH MATCHES</span><strong>{producing}</strong><small>ACROSS INGESTED SOURCES</small></div><div><span>CONTENT STATUS</span><strong>{stable} STABLE</strong><small>{tested} TEST · {rules.length - tested - stable} EXPERIMENTAL</small></div><div><span>EXECUTION PATH</span><strong>SQLITE</strong><small>OFFICIAL SYSMON PIPELINE</small></div></div>
    <section className="panel rule-library"><div className="rule-library-head"><span>RULE / ATTRIBUTION</span><span>ATT&CK COVERAGE</span><span>QUALITY</span><span>MATCHES</span><span>CONTROL</span></div>{rules.map((rule) => <article className={rule.enabled ? "" : "rule-disabled"} key={rule.id}><div><header><Severity value={rule.severity} /><span className="engine-badge sigma">Σ SIGMA</span></header><strong>{rule.name}</strong><small>{rule.id}</small><p>By {rule.author}</p></div><div className="rule-techniques">{rule.mitre_techniques.map((technique) => <span className="technique" key={technique}>{technique}</span>)}</div><div><span className={`quality ${rule.compatibility === "compatible" ? rule.status : "deprecated"}`} title={rule.last_error ?? undefined}>{rule.compatibility === "compatible" ? rule.status : "query error"}</span><small>{rule.backend}<br />{rule.pipeline}</small></div><div className={rule.match_count ? "match-count active" : "match-count"}><strong>{rule.match_count}</strong><small>EVENTS</small></div><div className="rule-actions"><button disabled={busy || rule.compatibility !== "compatible"} className={rule.enabled ? "enabled" : ""} aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.name}`} onClick={() => void toggleRule(rule.id, !rule.enabled)}>{rule.enabled ? "ON" : "OFF"}</button><a href={rule.source_url} target="_blank" rel="noreferrer" aria-label={`Open ${rule.name} source`}>↗</a></div></article>)}</section>
  </>;
}

function InvestigationDirectory({ investigations, selectInvestigation, navigate }: { investigations: Investigation[]; selectInvestigation: (item: Investigation) => void; navigate: (view: View) => void }) {
  const open = investigations.filter((item) => item.status === "OPEN");
  const closed = investigations.filter((item) => item.status === "CLOSED");
  return <>
    <div className="page-heading"><div><span className="eyebrow">STEP 3 · CASE MANAGEMENT</span><h1>Investigations</h1><p>Continue active work or review the immutable record of completed analyst decisions.</p></div><div className="record-count"><strong>{open.length}</strong><span>open · {closed.length} closed</span></div></div>
    <PageGuide title={open.length ? "Continue an open investigation" : closed.length ? "Active queue clear" : "Start from an alert"} detail={open.length ? "Open cases can accept evidence and hypotheses. A conclusive verdict closes the case and moves it to history." : closed.length ? "No investigation currently requires analyst action. Closed cases remain available below for audit and review." : "An investigation preserves evidence, hypotheses, agent actions, and the final human verdict."} steps={["Open an active case or start from Alerts", "Verify evidence and test a hypothesis", "Record a verdict to close or retain the case"]} action={!open.length ? { label: "Go to alerts", onClick: () => navigate("findings") } : undefined} />
    <div className="investigation-directory">
      <section className="panel"><div className="panel-head"><div><span className="eyebrow">ACTIVE QUEUE</span><h2>Open investigations</h2></div><span className="panel-count">{open.length}</span></div><div className="case-record-list">{open.map((item) => <button key={item.id} onClick={() => selectInvestigation(item)}><span><strong>{item.id}</strong><em>OPEN</em></span><b>{item.finding.title}</b><small>{item.evidence.length} evidence · {item.hypotheses.length} hypotheses · updated {dateTime(item.updated_at)}</small><i>Continue investigation →</i></button>)}{!open.length && <EmptyState title="No open investigations" detail="The active queue is clear. Start from an alert when new work requires analysis." />}</div></section>
      <section className="panel"><div className="panel-head"><div><span className="eyebrow">CASE HISTORY</span><h2>Closed investigations</h2></div><span className="panel-count">{closed.length}</span></div><div className="case-record-list archive">{closed.map((item) => <button key={item.id} onClick={() => selectInvestigation(item)}><span><strong>{item.id}</strong><em>{item.verdict}</em></span><b>{item.finding.title}</b><small>{item.evidence.length} evidence · {item.hypotheses.length} hypotheses · closed {dateTime(item.updated_at)}</small><i>View read-only record →</i></button>)}{!closed.length && <EmptyState title="No closed investigations" detail="Cases appear here after a conclusive human verdict." />}</div></section>
    </div>
  </>;
}

function InvestigationWorkspace({ investigation, investigations, selectInvestigation, closeInvestigation, refresh, inspectEvent, webMcp, navigate }: {
  investigation: Investigation | null;
  investigations: Investigation[];
  selectInvestigation: (item: Investigation) => void;
  closeInvestigation: () => void;
  refresh: () => Promise<void>;
  inspectEvent: (id: string) => void;
  webMcp: WebMcpAvailability;
  navigate: (view: View) => void;
}) {
  const [showHypothesisForm, setShowHypothesisForm] = useState(false);
  const [title, setTitle] = useState("");
  const [reasoning, setReasoning] = useState("");
  const [confidence, setConfidence] = useState(50);
  const [promptCopied, setPromptCopied] = useState(false);
  const [showAllRelatedEvents, setShowAllRelatedEvents] = useState(false);
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const caseSwitcherRef = useRef<HTMLDivElement>(null);

  useEffect(() => { setShowAllRelatedEvents(false); }, [investigation?.id]);
  useEffect(() => {
    if (!caseMenuOpen) return;
    const closeOnOutsideClick = (event: PointerEvent) => {
      if (!caseSwitcherRef.current?.contains(event.target as Node)) setCaseMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setCaseMenuOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [caseMenuOpen]);

  if (!investigation) return <InvestigationDirectory investigations={investigations} selectInvestigation={selectInvestigation} navigate={navigate} />;

  const createHypothesis = async (event: FormEvent) => {
    event.preventDefault();
    await api.createHypothesis(investigation.id, {
      title,
      reasoning,
      confidence,
      evidence_ids: investigation.evidence.map((item) => item.id),
      actor: "human",
    });
    setTitle("");
    setReasoning("");
    setConfidence(50);
    setShowHypothesisForm(false);
    await refresh();
  };
  const isClosed = investigation.status === "CLOSED";
  const setVerdict = async (verdict: string) => {
    const updated = await api.verdict(investigation.id, verdict);
    await refresh();
    if (updated.status === "CLOSED") closeInvestigation();
  };
  const firstUnpinnedEvent = investigation.finding.event_ids.find((eventId) => !investigation.evidence.some((item) => item.event_id === eventId));
  const visibleEventIds = showAllRelatedEvents ? investigation.finding.event_ids : investigation.finding.event_ids.slice(0, 8);
  const nextAction = isClosed
    ? { title: "Closed investigation record", detail: `The ${investigation.verdict?.toLowerCase()} verdict closed this case. Evidence, hypotheses, and activity remain available for audit but cannot be changed.`, label: "Return to case history", action: closeInvestigation }
    : !investigation.evidence.length
    ? { title: "Review the alert's related events", detail: "Open an event, confirm its important fields against the original source, then add it as evidence with why it matters.", label: "Open first event", action: () => firstUnpinnedEvent && inspectEvent(firstUnpinnedEvent) }
    : !investigation.hypotheses.length
      ? { title: "Explain what the evidence means", detail: "Create a hypothesis that cites the evidence you pinned and estimate your confidence.", label: "Create hypothesis", action: () => setShowHypothesisForm(true) }
      : !investigation.verdict
        ? { title: "Record the analyst decision", detail: "Review the evidence and hypothesis, then choose a final verdict in the decision panel.", label: "Go to verdict", action: () => document.getElementById("analyst-verdict")?.scrollIntoView({ behavior: "smooth", block: "center" }) }
        : { title: "Investigation decision recorded", detail: `The human verdict is ${investigation.verdict.toLowerCase()}. The case history remains available for review.`, label: "Review alerts", action: () => navigate("findings") };
  const verdicts = [
    ["BENIGN", "Expected or harmless activity"],
    ["SUSPICIOUS", "Concerning, but not confirmed"],
    ["INCIDENT", "Confirmed security incident"],
    ["INCONCLUSIVE", "Insufficient evidence"],
  ] as const;
  const prompt = "Investigate the active alert. Review related endpoint events, pin only the strongest evidence with a rationale, and create an evidence-linked hypothesis. Summarize your recommendation, but do not set the final verdict.";

  return <>
    <div className="page-heading investigation-heading"><div><span className="eyebrow">STEP 3 · {investigation.id} · {investigation.status}</span><h1>{investigation.finding.title}</h1><p>{investigation.finding.description}</p></div><div className="case-switcher" ref={caseSwitcherRef}><label id="active-investigation-label">{isClosed ? "CASE RECORD" : "ACTIVE INVESTIGATION"}</label><button className="case-select" type="button" aria-labelledby="active-investigation-label active-investigation-value" aria-haspopup="listbox" aria-expanded={caseMenuOpen} onClick={() => setCaseMenuOpen((current) => !current)}><span id="active-investigation-value"><strong>{investigation.id}</strong><em>{investigation.finding.title}</em></span><svg aria-hidden="true" viewBox="0 0 20 20"><path d="m5 7.5 5 5 5-5" /></svg></button>{caseMenuOpen && <div className="case-menu" role="listbox" aria-labelledby="active-investigation-label">{investigations.map((item) => <button type="button" role="option" aria-selected={item.id === investigation.id} className={item.id === investigation.id ? "selected" : ""} key={item.id} onClick={() => { setShowAllRelatedEvents(false); setCaseMenuOpen(false); selectInvestigation(item); }}><span><strong>{item.id}</strong><em>{item.status}</em></span><b>{item.finding.title}</b><small>{item.finding.rule_count} Sigma rules · {item.finding.matched_event_count} related events</small></button>)}</div>}</div></div>
    {isClosed && <aside className="closed-case-banner"><div><span>READ-ONLY CASE HISTORY</span><strong>{investigation.verdict} verdict · investigation closed</strong><p>This record is preserved for audit. Start or continue an open investigation to add evidence, hypotheses, or a new verdict.</p></div><button onClick={closeInvestigation}>View case history</button></aside>}
    <div className="case-progress" aria-label="Investigation progress"><div className="done"><i>✓</i><span>Understand alert</span><small>Review detection context</small></div><b /><div className={investigation.evidence.length ? "done" : "active"}><i>{investigation.evidence.length ? "✓" : "2"}</i><span>Collect evidence</span><small>{investigation.evidence.length ? `${investigation.evidence.length} verified` : "Verify related events"}</small></div><b /><div className={investigation.hypotheses.length ? "done" : investigation.evidence.length ? "active" : ""}><i>{investigation.hypotheses.length ? "✓" : "3"}</i><span>Test hypothesis</span><small>Explain what happened</small></div><b /><div className={investigation.verdict ? "done" : investigation.hypotheses.length ? "active" : ""}><i>{investigation.verdict ? "✓" : "4"}</i><span>Record verdict</span><small>Human-only decision</small></div></div>
    <aside className="next-action"><div><span>{isClosed ? "CASE STATUS" : "NEXT BEST ACTION"}</span><strong>{nextAction.title}</strong><p>{nextAction.detail}</p></div><button className="primary" onClick={nextAction.action}>{nextAction.label} →</button></aside>

    <div className="investigation-grid redesigned">
      <main className="case-workbench panel">
        <section className="work-section">
          <div className="section-title"><span>01</span><h2>Review related events</h2><em>{investigation.finding.matched_event_count} RELATED EVENTS</em></div>
          <p className="section-intro">Start with the events that caused this alert. Opening an event does not make it evidence—you decide that only after checking the details and explaining why the event supports or challenges your investigation.</p>
          <aside className="evidence-definition"><strong>What counts as evidence?</strong><p>A verified event with a specific reason it matters. Good evidence points to an observable field—such as a process, command line, user, host, or network destination—and states what it supports or refutes.</p></aside>
          <div className="alert-brief"><div><Severity value={investigation.finding.severity} /><strong>{investigation.finding.risk_score}/100 risk · {investigation.finding.confidence}% detection confidence</strong></div><p>These events triggered the alert. Open each relevant record, compare normalized and raw data, and pin only what supports or refutes your explanation.</p></div>
          <div className="related-events">{visibleEventIds.map((eventId, index) => {
            const pinned = investigation.evidence.some((item) => item.event_id === eventId);
            const event = investigation.finding.events?.find((item) => item.id === eventId);
            return <button key={eventId} onClick={() => inspectEvent(eventId)}><span>{String(index + 1).padStart(2, "0")}</span><div><strong>{event ? `${basename(event.process)} · ${event.event_type}` : eventId}</strong><small>{event ? `${dateTime(event.timestamp)} · ${event.host ?? "unknown host"}` : "Inspect normalized fields and the original source record"}</small></div><em className={pinned ? "pinned" : ""}>{pinned ? "✓ EVIDENCE ADDED" : "OPEN EVENT →"}</em></button>;
          })}</div>
          {investigation.finding.event_ids.length > 8 && <div className="event-disclosure"><span>{showAllRelatedEvents ? `Showing all ${investigation.finding.event_ids.length} related events` : `Showing the first 8 of ${investigation.finding.event_ids.length} related events`}</span><button onClick={() => setShowAllRelatedEvents((current) => !current)}>{showAllRelatedEvents ? "Show fewer" : `Show all ${investigation.finding.event_ids.length} events`}</button></div>}
        </section>

        <section className="work-section">
          <div className="section-title"><span>02</span><h2>Evidence selected for this investigation</h2><em>{investigation.evidence.length} ITEMS</em></div>
          <p className="section-intro">This board contains only events a human or agent deliberately verified and added with a rationale. Use it as the factual basis for the hypothesis—not as a dumping ground for every related event.</p>
          <div className="evidence-list">
            {investigation.evidence.map((item) => <button key={item.id} onClick={() => inspectEvent(item.event_id)}><div className="evidence-top"><span className="evidence-id">{item.id}</span><span className={`actor ${item.added_by}`}>{item.added_by}</span><time>{time(item.created_at)}</time></div><strong>{basename(item.event.process)} · {item.event.event_type}</strong><p><span className="evidence-label">WHY IT MATTERS</span>{item.rationale}</p><code>{item.event_id} · {item.event.command_line ?? item.event.destination_ip ?? item.event.host}</code></button>)}
            {!investigation.evidence.length && <EmptyState title="No evidence selected yet" detail="Open a related event above, verify its fields, explain why it matters, and add it to this investigation. The agent can perform the same bounded action." />}
          </div>
        </section>

        <section className="work-section hypotheses-section">
          <div className="section-title"><span>03</span><h2>Test a hypothesis</h2><em>{investigation.hypotheses.length} RECORDED</em>{!isClosed && <button onClick={() => setShowHypothesisForm(!showHypothesisForm)}>{showHypothesisForm ? "Cancel" : "+ New hypothesis"}</button>}</div>
          <p className="section-intro">A hypothesis is your evidence-backed explanation of the activity. It should say what likely happened, cite the selected evidence, and make uncertainty explicit.</p>
          {showHypothesisForm && <form className="hypothesis-form expanded" onSubmit={createHypothesis}><label>Hypothesis title<input required minLength={3} placeholder="Example: Encoded PowerShell launched a credential-access chain" value={title} onChange={(event) => setTitle(event.target.value)} /></label><label>Evidence-based reasoning<textarea required minLength={3} placeholder="Explain what happened, which evidence supports it, and what uncertainty remains…" value={reasoning} onChange={(event) => setReasoning(event.target.value)} /></label><label>Confidence: {confidence}%<input type="range" min="0" max="100" step="5" value={confidence} onChange={(event) => setConfidence(Number(event.target.value))} /></label><small>{investigation.evidence.length} pinned evidence item{investigation.evidence.length === 1 ? "" : "s"} will be linked automatically.</small><button className="primary" disabled={!investigation.evidence.length}>Save hypothesis</button></form>}
          <div className="hypothesis-list">{investigation.hypotheses.map((item) => <article key={item.id}><header><span>{item.id}</span><em>{item.confidence}% confidence</em></header><strong>{item.title}</strong><p>{item.reasoning}</p><footer><span className={`actor ${item.created_by}`}>{item.created_by}</span><span>{item.status}</span><span>{item.evidence_ids.length} linked evidence</span></footer></article>)}{!investigation.hypotheses.length && !showHypothesisForm && <EmptyState title="No hypothesis yet" detail="Pin evidence first, then document the explanation you are testing. Both humans and agents can contribute hypotheses." />}</div>
        </section>
      </main>

      <aside className="case-sidebar">
        <section className="panel context-card">
          <div className="section-title"><span>i</span><h2>Alert context</h2></div>
          <dl><dt>AFFECTED HOST</dt><dd>{investigation.finding.entities.hosts?.[0] ?? "Unknown"}</dd><dt>USER</dt><dd>{investigation.finding.entities.users?.[0] ?? "Unknown"}</dd><dt>PROCESS</dt><dd>{investigation.finding.entities.processes?.map(basename).join(", ") || "Unknown"}</dd><dt>TIME WINDOW</dt><dd>{dateTime(investigation.finding.first_seen)} to {dateTime(investigation.finding.last_seen)}</dd><dt>DETECTION</dt><dd>{investigation.finding.rule_count} Sigma rules · {investigation.finding.signal_count} matches</dd><dt>MITRE ATT&CK</dt><dd><div className="technique-stack">{(investigation.finding.sigma?.techniques ?? [investigation.finding.mitre_technique]).filter((technique): technique is string => Boolean(technique)).map((technique) => <span className="technique" key={technique}>{technique}</span>)}</div></dd></dl>
          {investigation.finding.sigma && <details className="rule-detail"><summary>View detection logic and source</summary><dl><dt>RULE</dt><dd>{investigation.finding.rule_id}</dd><dt>STATUS</dt><dd>{investigation.finding.sigma.status}</dd><dt>AUTHOR</dt><dd>{investigation.finding.sigma.author}</dd></dl><code>{investigation.finding.sigma.compiled_query}</code><a href={investigation.finding.sigma.source_url} target="_blank" rel="noreferrer">Open Sigma rule source ↗</a></details>}
        </section>

        <section className="panel collaboration-card">
          <div className="section-title"><span>AI</span><h2>Agent collaboration</h2></div>
          <div className={`webmcp-card ${webMcp.available ? "online" : ""}`} title={webMcp.detail}><div><i /><strong>{webMcp.available ? "Browser agent tools ready" : "Browser agent not connected"}</strong></div><span>{webMcp.available ? `${webMcp.count} bounded tools share this active investigation` : webMcp.detail}</span></div>
          <p>{isClosed ? "This case is no longer exposed as an active agent workspace. Its evidence, hypotheses, provenance, and tool activity remain readable for audit." : "The analyst and agent use the same evidence and hypotheses. You can complete every step manually; only the human can set the verdict."}</p>
          <div className="prompt-card"><span className="eyebrow">OPTIONAL AGENT TASK</span><p>{prompt}</p><button onClick={() => { void navigator.clipboard?.writeText(prompt); setPromptCopied(true); }}>{promptCopied ? "✓ Prompt copied" : "Copy prompt for agent"}</button></div>
        </section>

        <section className="panel verdict-card" id="analyst-verdict">
          <div className="section-title"><span>04</span><h2>Analyst verdict</h2></div>
          <p>Choose the outcome only after reviewing the selected evidence and hypothesis. The browser agent may recommend an outcome, but this decision is intentionally human-only.</p>
          <div className="verdict-list">{verdicts.map(([value, description]) => <button disabled={isClosed} className={investigation.verdict === value ? "selected" : ""} key={value} onClick={() => setVerdict(value)}><span>{investigation.verdict === value ? "●" : "○"}</span><div><strong>{value === "INCIDENT" ? "Confirmed incident" : value.charAt(0) + value.slice(1).toLowerCase()}</strong><small>{description}</small></div></button>)}</div>
        </section>

        <details className="panel activity-card"><summary>Investigation activity ({investigation.timeline.length})</summary><div className="timeline">{investigation.timeline.map((item) => <div className="timeline-row" key={item.id}><i className={item.actor} /><time>{time(item.created_at)}</time><div><strong>{item.event_type.replaceAll("_", " ")}</strong><p>{item.summary}</p></div><span className={`actor ${item.actor}`}>{item.actor}</span></div>)}</div></details>
      </aside>
    </div>
  </>;
}

function EventDrawer({ event, investigation, close, changed }: { event: SecurityEvent; investigation: Investigation | null; close: () => void; changed: () => Promise<void> }) {
  const [rawMode, setRawMode] = useState(false);
  const [rationale, setRationale] = useState("");
  const [busy, setBusy] = useState(false);
  const alreadyPinned = investigation?.evidence.some((item) => item.event_id === event.id);
  const investigationClosed = investigation?.status === "CLOSED";
  const pin = async () => {
    if (!investigation) return;
    setBusy(true);
    try { await api.addEvidence(investigation.id, [event.id], rationale, "human"); await changed(); } finally { setBusy(false); }
  };
  return <div className="drawer-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) close(); }}><aside className="event-drawer"><header><div><span className="event-id">{event.id}</span><h2>{investigationClosed ? "Review archived event" : "Review event for evidence"}</h2></div><button aria-label="Close event details" onClick={close}>×</button></header><div className="drawer-tabs"><button className={!rawMode ? "active" : ""} onClick={() => setRawMode(false)}>Normalized fields</button><button className={rawMode ? "active" : ""} onClick={() => setRawMode(true)}>Original source</button></div><div className="drawer-guidance"><strong>{rawMode ? "Confirm the source record" : "Understand what happened"}</strong><span>{rawMode ? "Compare the original event with the normalized fields. Long source values wrap so important details are not hidden off-screen." : "Review the process, user, host, command line, and network fields. Switch to Original source before treating the event as evidence."}</span></div>{rawMode ? <pre>{typeof event.raw === "string" ? event.raw : JSON.stringify(event.raw, null, 2)}</pre> : <div className="detail-grid">{Object.entries(event).filter(([key, value]) => !["raw", "additional_fields", "finding_ids"].includes(key) && value).map(([key, value]) => <div key={key}><span>{key.replaceAll("_", " ")}</span><code>{String(value)}</code></div>)}<div className="wide"><span>additional fields</span><pre>{JSON.stringify(event.additional_fields, null, 2)}</pre></div></div>}<div className="drawer-action"><label><strong>{investigationClosed ? "Evidence rationale" : "Why does this event matter?"}</strong><span>{investigationClosed ? "This investigation is closed. Existing evidence remains available in the case record, but no new evidence can be added." : "Name the observable detail and state whether it supports or challenges your explanation."}</span><textarea disabled={investigationClosed} required minLength={3} value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder="Example: certutil.exe downloaded an executable from an external URL, supporting the tool-transfer alert." /></label><button className="primary" disabled={!investigation || investigationClosed || alreadyPinned || busy || rationale.trim().length < 3} onClick={pin}>{investigationClosed ? "Investigation closed" : alreadyPinned ? "Already added" : investigation ? "Add to investigation" : "Open an investigation first"}</button></div></aside></div>;
}

function ResetDialog({ value, setValue, busy, cancel, confirm }: { value: string; setValue: (value: string) => void; busy: boolean; cancel: () => void; confirm: () => Promise<void> }) {
  return <div className="modal-backdrop" role="presentation" onKeyDown={(event) => { if (event.key === "Escape" && !busy) cancel(); }} onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) cancel(); }}><section className="reset-dialog" role="dialog" aria-modal="true" aria-labelledby="reset-title" aria-describedby="reset-description"><div className="danger-mark">!</div><span className="eyebrow">DESTRUCTIVE ACTION</span><h2 id="reset-title">Reset investigation workspace?</h2><p id="reset-description">This permanently removes ingested events, detections, evidence, hypotheses, investigations, and incidents. The bundled open-source source files and Sigma rules remain available to ingest again.</p><label>Type <strong>RESET</strong> to confirm<input autoFocus value={value} onChange={(event) => setValue(event.target.value)} placeholder="RESET" /></label><footer><button className="secondary" onClick={cancel} disabled={busy}>Cancel</button><button className="danger" onClick={() => void confirm()} disabled={busy || value !== "RESET"}>{busy ? "Resetting…" : "Reset workspace"}</button></footer></section></div>;
}
