export type Counts = {
  raw_logs: number;
  normalized_events: number;
  rules: number;
  findings: number;
  open_findings: number;
  investigations: number;
  open_investigations: number;
};

export type Workspace = {
  application: string;
  dataset: string;
  ingested: boolean;
  counts: Counts;
  webmcp_tools: number;
  datasets: Dataset[];
  detection_engine: {
    name: string;
    backend: string;
    pipeline: string;
    official_rules: number;
    available_rules: number;
    enabled_rules: number;
    matched_rules: number;
    signal_count: number;
    distinct_detected_events: number;
    suppressed_duplicates: number;
  };
  already_ingested?: boolean;
  rejected?: number;
  findings_created?: number;
};

export type Dataset = {
  id: string;
  name: string;
  provider: string;
  telemetry: string;
  technique: string;
  provenance: string;
  license: string;
  source_url: string | null;
  available_events: number;
  ingested_events: number;
  ingested: boolean;
  local_file: string;
};

export type SecurityEvent = {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  host: string | null;
  user: string | null;
  process: string | null;
  parent_process: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  command_line: string | null;
  additional_fields: Record<string, unknown>;
  raw?: Record<string, unknown> | string;
  finding_ids?: string[];
};

export type Finding = {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  timestamp: string;
  status: string;
  entities: {
    hosts?: string[];
    users?: string[];
    processes?: string[];
  };
  mitre_technique: string | null;
  matched_event_count: number;
  signal_count: number;
  suppressed_signal_count: number;
  rule_ids: string[];
  rule_count: number;
  risk_score: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
  event_ids: string[];
  events?: SecurityEvent[];
  engine: "sigma" | "native";
  sigma: {
    status: string;
    author: string;
    license: string;
    source_url: string;
    backend: string;
    pipeline: string;
    compiled_query: string;
    tags: string[];
    techniques: string[];
  } | null;
};

export type SigmaRule = {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string;
  author: string;
  mitre_technique: string | null;
  mitre_techniques: string[];
  source_url: string;
  backend: string;
  pipeline: string;
  match_count: number;
  enabled: boolean;
  compatibility: "compatible" | "query_error";
  last_error: string | null;
};

export type Evidence = {
  id: string;
  event_id: string;
  rationale: string;
  added_by: string;
  created_at: string;
  event: SecurityEvent;
};

export type Hypothesis = {
  id: string;
  title: string;
  reasoning: string;
  status: "OPEN" | "SUPPORTED" | "REFUTED";
  confidence: number;
  evidence_ids: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type TimelineEvent = {
  id: number;
  event_type: string;
  actor: string;
  summary: string;
  detail: Record<string, unknown>;
  created_at: string;
};

export type Investigation = {
  id: string;
  status: string;
  verdict: string | null;
  created_at: string;
  updated_at: string;
  finding: Finding;
  evidence: Evidence[];
  hypotheses: Hypothesis[];
  timeline: TimelineEvent[];
};
