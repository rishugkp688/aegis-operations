import type { Finding, Investigation, SecurityEvent, SigmaRule, Workspace } from "./types";

const API_ROOT = import.meta.env.VITE_API_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(payload.detail ?? `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  workspace: () => request<Workspace>("/api/workspace"),
  ingest: (datasetId = "splunk-t1003-001") =>
    request<Workspace>(`/api/datasets/${datasetId}/ingest`, { method: "POST" }),
  events: (filters: Record<string, string | number | undefined> = {}) => {
    const query = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== "") query.set(key, String(value));
    });
    return request<{ total: number; items: SecurityEvent[] }>(`/api/events?${query}`);
  },
  event: (eventId: string) => request<SecurityEvent>(`/api/events/${eventId}`),
  eventContext: (eventId: string, before = 3, after = 3) =>
    request<{ target_event_id: string; items: SecurityEvent[] }>(`/api/events/${eventId}/context`, {
      method: "POST",
      body: JSON.stringify({ before, after }),
    }),
  aggregate: (input: Record<string, unknown>) =>
    request<{ group_by: string; window_minutes: number; items: { value: string; count: number }[] }>(
      "/api/events/aggregate",
      { method: "POST", body: JSON.stringify(input) },
    ),
  findings: () => request<Finding[]>("/api/findings"),
  rules: () => request<SigmaRule[]>("/api/rules"),
  setRuleEnabled: (ruleId: string, enabled: boolean) =>
    request<{ rule: SigmaRule; workspace: Workspace }>(`/api/rules/${ruleId}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
  reset: () => request<{ reset: boolean; workspace: Workspace }>("/api/workspace/reset", {
    method: "POST",
    body: JSON.stringify({ confirmation: "RESET" }),
  }),
  finding: (findingId: string) => request<Finding>(`/api/findings/${findingId}`),
  investigations: () => request<Investigation[]>("/api/investigations"),
  investigation: (investigationId: string) =>
    request<Investigation>(`/api/investigations/${investigationId}`),
  startInvestigation: (findingId: string) =>
    request<Investigation>(`/api/findings/${findingId}/investigations`, {
      method: "POST",
      body: JSON.stringify({ actor: "human" }),
    }),
  addEvidence: (investigationId: string, eventIds: string[], rationale: string, actor = "human") =>
    request<{ created_evidence_ids: string[]; investigation: Investigation }>(
      `/api/investigations/${investigationId}/evidence`,
      {
        method: "POST",
        body: JSON.stringify({ event_ids: eventIds, rationale, actor }),
      },
    ),
  createHypothesis: (
    investigationId: string,
    input: { title: string; reasoning: string; confidence: number; evidence_ids: string[]; actor?: string },
  ) =>
    request<{ hypothesis_id: string; investigation: Investigation }>(
      `/api/investigations/${investigationId}/hypotheses`,
      { method: "POST", body: JSON.stringify(input) },
    ),
  updateHypothesis: (investigationId: string, hypothesisId: string, input: Record<string, unknown>) =>
    request<{ hypothesis_id: string; investigation: Investigation }>(
      `/api/investigations/${investigationId}/hypotheses/${hypothesisId}`,
      { method: "PATCH", body: JSON.stringify(input) },
    ),
  verdict: (investigationId: string, verdict: string) =>
    request<Investigation>(`/api/investigations/${investigationId}/verdict`, {
      method: "POST",
      body: JSON.stringify({ verdict, actor: "human" }),
    }),
};
