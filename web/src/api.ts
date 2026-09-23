// Typed client for the REST API. Types mirror internal/domain.

export type Health = "healthy" | "degraded" | "down";
export type Severity = "low" | "medium" | "high" | "critical";

export interface Incident {
  id: string;
  title: string;
  description: string;
  target_host: string;
  target_port?: number;
  status: "open" | "analyzed";
  created_at: string;
}

export interface ToolExecution {
  id: string;
  tool_name: string;
  status: "succeeded" | "failed";
  error?: string;
  duration_ms: number;
}

export interface Evidence {
  id: string;
  tool_execution_id: string;
  source: string;
  health: Health;
  summary: string;
}

export interface Analysis {
  summary: string;
  root_cause: string;
  confidence: number;
  severity: Severity;
  evidence: { source: string; description: string }[];
  possible_causes: string[];
  recommended_actions: string[];
}

export interface InvestigationRecord {
  investigation: { id: string; status: string; scenario?: string; error?: string };
  tool_executions: ToolExecution[];
  evidence: Evidence[];
  report?: { provider: string; analysis: Analysis };
}

export interface CreateIncident {
  title: string;
  description: string;
  target_host: string;
  target_port?: number;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: { result?: InvestigationRecord } = {},
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error?.message ?? `HTTP ${res.status}`, res.status, data);
  return data as T;
}

export const api = {
  listIncidents: () => request<{ incidents: Incident[] }>("GET", "/api/v1/incidents?limit=100").then((r) => r.incidents),
  getIncident: (id: string) => request<Incident>("GET", `/api/v1/incidents/${id}`),
  createIncident: (body: CreateIncident) => request<Incident>("POST", "/api/v1/incidents", body),
  investigate: (id: string, scenario: string) =>
    request<InvestigationRecord>("POST", `/api/v1/incidents/${id}/investigate`, scenario ? { scenario } : {}),
  report: (id: string) => request<InvestigationRecord>("GET", `/api/v1/incidents/${id}/report`),
  ready: () => request<{ status: string }>("GET", "/ready"),
};

export const SCENARIOS = ["healthy", "packet_loss", "dns_failure", "tcp_failure", "high_latency"] as const;
