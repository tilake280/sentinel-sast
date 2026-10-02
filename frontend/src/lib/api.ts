// Typed access to the gateway's read API.
//
// Everything here runs on the Next.js server: pages are Server Components and
// call these directly, so GATEWAY_URL is never sent to the browser and the
// gateway does not need to allow cross-origin requests.

const GATEWAY_URL = (process.env.GATEWAY_URL ?? "http://localhost:3001").replace(/\/+$/, "");

export type Verdict = "ESCALATED" | "SUPPRESSED" | "UNTRIAGED";
export type ScanStatus = "PENDING" | "COMPLETED" | "FAILED";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Scan {
  id: string;
  repository: string;
  commit: string;
  ref: string;
  status: ScanStatus;
  error?: string;
  files_queued: number;
  files_scanned: number;
  findings: number;
  escalated: number;
  suppressed: number;
  untriaged: number;
  worker_version?: string;
  created_at: string;
  completed_at: string | null;
}

export interface TraceStep {
  line: number;
  snippet: string;
  description: string;
}

export interface Finding {
  id: number;
  file: string;
  line: number;
  column: number;
  vulnerability: string;
  class: string;
  rule_id: string;
  cwe: string;
  severity: Severity;
  confidence: string;
  message: string;
  snippet: string;
  remediation: string;
  function: string;
  trace: TraceStep[] | null;
  verdict: Verdict;
  triage_confidence: number;
  triage_reason: string;
}

export interface Stats {
  scans: number;
  pending: number;
  completed: number;
  failed: number;
  findings: number;
  escalated: number;
  suppressed: number;
  untriaged: number;
}

// A failed request is a value, not an exception. The pages render a specific
// message for "the gateway is down" rather than a generic error boundary, and
// they must never fall back to placeholder numbers.
export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string };

async function get<T>(path: string): Promise<Result<T>> {
  let response: Response;
  try {
    response = await fetch(`${GATEWAY_URL}${path}`, {
      // Scan state changes from one second to the next; never serve it stale.
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return {
      ok: false,
      status: 0,
      error: `Could not reach the gateway at ${GATEWAY_URL}.`,
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      error: `The gateway answered ${response.status} for ${path}.`,
    };
  }

  try {
    return { ok: true, data: (await response.json()) as T };
  } catch {
    return { ok: false, status: response.status, error: "The gateway sent a response that is not JSON." };
  }
}

export const gatewayUrl = GATEWAY_URL;

export function getStats() {
  return get<Stats>("/api/v1/stats");
}

export function getScans(limit = 50) {
  return get<{ scans: Scan[] }>(`/api/v1/scans?limit=${limit}`);
}

export function getScan(id: string) {
  return get<{ scan: Scan; findings: Finding[] }>(`/api/v1/scans/${encodeURIComponent(id)}`);
}
