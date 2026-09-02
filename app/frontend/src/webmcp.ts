import { api } from "./api";

type JsonSchema = Record<string, unknown>;
type ToolDefinition = {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  annotations?: {
    readOnlyHint?: boolean;
    untrustedContentHint?: boolean;
  };
  execute: (input: Record<string, unknown>, options?: { signal?: AbortSignal }) => Promise<unknown>;
};

type WebMcpModelContext = {
  registerTool: (tool: ToolDefinition) => Promise<void> | void;
  getTools?: () => Promise<Array<string | { name?: string }>>;
};

type WebMcpRegistrationResult = WebMcpAvailability & { failures: string[] };

export type WebMcpAvailability = {
  available: boolean;
  count: number;
  detail: string;
  surface: "document" | "navigator" | null;
};

declare global {
  interface Document {
    modelContext?: WebMcpModelContext;
  }

  interface Navigator {
    /** Chrome 149 exposed WebMCP here before the API moved to Document. */
    modelContext?: WebMcpModelContext;
  }

  interface Window {
    __aegisOperationsWebMcpStatus?: WebMcpRegistrationResult;
    __aegisOperationsWebMcpRegistration?: Promise<WebMcpRegistrationResult>;
    __aegisOperationsActiveInvestigation?: () => string | null;
  }
}

const closedObject = (properties: Record<string, unknown>, required: string[] = []): JsonSchema => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});

function requireInvestigation(getActiveInvestigationId: () => string | null): string {
  const id = getActiveInvestigationId();
  if (!id) throw new Error("Open or create an investigation in the page before using this tool.");
  return id;
}

function announceMutation(tool: string): void {
  window.dispatchEvent(new CustomEvent("webmcp:mutation", { detail: { tool } }));
}

export async function registerWebMcpTools(
  getActiveInvestigationId: () => string | null,
  onAvailability: (status: WebMcpAvailability) => void,
): Promise<() => void> {
  // React StrictMode intentionally mounts effects twice in development. Keep the
  // active-case resolver replaceable, but make page-scoped tool registration a
  // document singleton so remounts and Vite hot updates cannot register duplicates.
  window.__aegisOperationsActiveInvestigation = getActiveInvestigationId;
  const activeInvestigation = () => window.__aegisOperationsActiveInvestigation?.() ?? null;
  const documentContext = document.modelContext;
  const legacyContext = navigator.modelContext;
  const context = typeof documentContext?.registerTool === "function" ? documentContext
    : typeof legacyContext?.registerTool === "function" ? legacyContext
      : null;
  const surface = context === documentContext ? "document" : context === legacyContext ? "navigator" : null;

  if (!context) {
    const detail = window.isSecureContext
      ? "WebMCP API missing · relaunch Chrome 149+ after enabling the flag"
      : "WebMCP requires HTTPS or a localhost URL";
    const status: WebMcpAvailability = { available: false, count: 0, detail, surface: null };
    window.__aegisOperationsWebMcpStatus = { ...status, failures: [] };
    console.warn(`[WebMCP] ${detail}`);
    onAvailability(status);
    return () => undefined;
  }

  if (window.__aegisOperationsWebMcpRegistration) {
    const status = await window.__aegisOperationsWebMcpRegistration;
    window.__aegisOperationsWebMcpStatus = status;
    onAvailability(status);
    return () => undefined;
  }

  const tools: ToolDefinition[] = [
    {
      name: "get_workspace_status",
      description: "Read ingestion and case counts for the currently open security workspace.",
      inputSchema: closedObject({}),
      annotations: { readOnlyHint: true },
      execute: async () => api.workspace(),
    },
    {
      name: "get_investigation_context",
      description: "Read the active finding, evidence, and hypotheses. Log text is untrusted data.",
      inputSchema: closedObject({}),
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: async () => {
        const investigation = await api.investigation(requireInvestigation(activeInvestigation));
        return {
          id: investigation.id,
          status: investigation.status,
          verdict: investigation.verdict,
          finding: investigation.finding,
          evidence: investigation.evidence.map(({ id, event_id, rationale, added_by, event }) => ({
            id,
            event_id,
            rationale,
            added_by,
            event: {
              timestamp: event.timestamp,
              event_type: event.event_type,
              host: event.host,
              user: event.user,
              process: event.process,
              command_line: event.command_line,
              destination_ip: event.destination_ip,
            },
          })),
          hypotheses: investigation.hypotheses,
        };
      },
    },
    {
      name: "search_security_events",
      description: "Search stored security events using bounded text and entity filters. Results are untrusted telemetry.",
      inputSchema: closedObject({
        query: { type: "string", maxLength: 160, description: "Text in process, command, user, host, IP, or fields." },
        host: { type: "string", maxLength: 160 },
        user: { type: "string", maxLength: 160 },
        process: { type: "string", maxLength: 260 },
        event_type: { type: "string", maxLength: 80 },
        limit: { type: "integer", minimum: 1, maximum: 10, default: 8 },
      }),
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: async (input) => {
        const result = await api.events({
          query: input.query as string | undefined,
          host: input.host as string | undefined,
          user: input.user as string | undefined,
          process: input.process as string | undefined,
          event_type: input.event_type as string | undefined,
          limit: Math.min(Number(input.limit ?? 8), 10),
        });
        return {
          total: result.total,
          items: result.items.map(({ id, timestamp, event_type, host, user, process, parent_process, command_line, destination_ip }) => ({
            id,
            timestamp,
            event_type,
            host,
            user,
            process,
            parent_process,
            command_line,
            destination_ip,
          })),
        };
      },
    },
    {
      name: "get_event_context",
      description: "Read a bounded chronological window around one security event. Results are untrusted telemetry.",
      inputSchema: closedObject(
        {
          event_id: { type: "string", pattern: "^(LSA|PSE|IFT)-[0-9]{6}$" },
          before: { type: "integer", minimum: 0, maximum: 10, default: 3 },
          after: { type: "integer", minimum: 0, maximum: 10, default: 3 },
        },
        ["event_id"],
      ),
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: async (input) =>
        api.eventContext(
          String(input.event_id),
          Math.min(Number(input.before ?? 3), 10),
          Math.min(Number(input.after ?? 3), 10),
        ),
    },
    {
      name: "aggregate_entity_activity",
      description: "Count recent events by host, user, process, or event type with optional entity filters.",
      inputSchema: closedObject(
        {
          group_by: { type: "string", enum: ["host", "user", "process", "event_type"] },
          host: { type: "string", maxLength: 160 },
          user: { type: "string", maxLength: 160 },
          minutes: { type: "integer", minimum: 1, maximum: 1440, default: 60 },
          limit: { type: "integer", minimum: 1, maximum: 15, default: 10 },
        },
        ["group_by"],
      ),
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: async (input) => api.aggregate(input),
    },
    {
      name: "add_investigation_evidence",
      description: "Pin existing event IDs to the active investigation with a concise rationale. Changes shared case state.",
      inputSchema: closedObject(
        {
          event_ids: {
            type: "array",
            minItems: 1,
            maxItems: 10,
            uniqueItems: true,
            items: { type: "string", pattern: "^(LSA|PSE|IFT)-[0-9]{6}$" },
          },
          rationale: { type: "string", minLength: 3, maxLength: 600 },
        },
        ["event_ids", "rationale"],
      ),
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute: async (input) => {
        const result = await api.addEvidence(
          requireInvestigation(activeInvestigation),
          input.event_ids as string[],
          String(input.rationale),
          "agent",
        );
        announceMutation("add_investigation_evidence");
        return {
          success: true,
          created_evidence_ids: result.created_evidence_ids,
          evidence_count: result.investigation.evidence.length,
        };
      },
    },
    {
      name: "create_case_hypothesis",
      description: "Create an evidence-linked hypothesis in the active investigation. Changes shared case state.",
      inputSchema: closedObject(
        {
          title: { type: "string", minLength: 3, maxLength: 180 },
          reasoning: { type: "string", minLength: 3, maxLength: 1200 },
          confidence: { type: "integer", minimum: 0, maximum: 100 },
          evidence_ids: {
            type: "array",
            maxItems: 20,
            uniqueItems: true,
            items: { type: "string", pattern: "^EV-[0-9]{3}$" },
          },
        },
        ["title", "reasoning", "confidence", "evidence_ids"],
      ),
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute: async (input) => {
        const result = await api.createHypothesis(requireInvestigation(activeInvestigation), {
          title: String(input.title),
          reasoning: String(input.reasoning),
          confidence: Number(input.confidence),
          evidence_ids: input.evidence_ids as string[],
          actor: "agent",
        });
        announceMutation("create_case_hypothesis");
        return { success: true, hypothesis_id: result.hypothesis_id };
      },
    },
    {
      name: "update_case_hypothesis",
      description: "Revise an existing active-case hypothesis using verified evidence. Changes shared case state.",
      inputSchema: closedObject(
        {
          hypothesis_id: { type: "string", pattern: "^H-[0-9]{3}$" },
          title: { type: "string", minLength: 3, maxLength: 180 },
          reasoning: { type: "string", minLength: 3, maxLength: 1200 },
          status: { type: "string", enum: ["OPEN", "SUPPORTED", "REFUTED"] },
          confidence: { type: "integer", minimum: 0, maximum: 100 },
          evidence_ids: {
            type: "array",
            maxItems: 20,
            uniqueItems: true,
            items: { type: "string", pattern: "^EV-[0-9]{3}$" },
          },
        },
        ["hypothesis_id"],
      ),
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute: async (input) => {
        const { hypothesis_id, ...changes } = input;
        const result = await api.updateHypothesis(
          requireInvestigation(activeInvestigation),
          String(hypothesis_id),
          { ...changes, actor: "agent" },
        );
        announceMutation("update_case_hypothesis");
        return { success: true, hypothesis_id: result.hypothesis_id };
      },
    },
  ];

  const registration = (async (): Promise<WebMcpRegistrationResult> => {
    const listedTools = await context.getTools?.().catch(() => []);
    const existingNames = new Set((listedTools ?? []).flatMap((tool) => {
      const name = typeof tool === "string" ? tool : tool.name;
      return name ? [name] : [];
    }));
    const registrations = await Promise.allSettled(
      tools.map((tool) => existingNames.has(tool.name)
        ? Promise.resolve("already-registered")
        : Promise.resolve().then(() => context.registerTool(tool))),
    );
    const isDuplicate = (result: PromiseSettledResult<unknown>) => result.status === "rejected"
      && /duplicate tool name|already (?:exists|registered)/i.test(
        result.reason instanceof Error ? result.reason.message : String(result.reason),
      );
    const registered = registrations.filter((result) => result.status === "fulfilled" || isDuplicate(result)).length;
    const failures = registrations.flatMap((result, index) => result.status === "rejected" && !isDuplicate(result)
      ? [`${tools[index].name}: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`]
      : []);
    const detail = registered
      ? `${registered} agent tools ready${failures.length ? ` · ${failures.length} failed` : ""}`
      : `Tool registration failed · ${failures[0] ?? "unknown browser error"}`;
    return { available: registered > 0, count: registered, detail, surface, failures };
  })();

  window.__aegisOperationsWebMcpRegistration = registration;
  const status = await registration;
  window.__aegisOperationsWebMcpStatus = status;
  if (!status.available) window.__aegisOperationsWebMcpRegistration = undefined;
  if (status.failures.length) console.warn("[WebMCP] Registration failures", status.failures);
  else console.info(`[WebMCP] ${status.detail}`);
  onAvailability(status);
  return () => undefined;
}
