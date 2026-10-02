import type { ScanStatus, Severity, Verdict } from "@/lib/api";

const base =
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium tracking-wide whitespace-nowrap";

const verdictStyle: Record<Verdict, string> = {
  ESCALATED: "border-red-500/40 bg-red-500/10 text-red-300",
  SUPPRESSED: "border-purple-500/40 bg-purple-500/10 text-purple-300",
  UNTRIAGED: "border-amber-500/40 bg-amber-500/10 text-amber-300",
};

const verdictTitle: Record<Verdict, string> = {
  ESCALATED: "Triaged: not similar to any previously dismissed finding",
  SUPPRESSED: "Triaged: matches a previously dismissed finding",
  UNTRIAGED: "No verdict: the triage layer was disabled or unreachable",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`${base} ${verdictStyle[verdict] ?? verdictStyle.UNTRIAGED}`} title={verdictTitle[verdict]}>
      {verdict}
    </span>
  );
}

const severityStyle: Record<Severity, string> = {
  CRITICAL: "border-red-500/50 bg-red-600/20 text-red-200",
  HIGH: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-yellow-500/40 bg-yellow-500/10 text-yellow-200",
  LOW: "border-slate-500/40 bg-slate-500/10 text-slate-300",
  INFO: "border-slate-600/40 bg-slate-600/10 text-slate-400",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${base} ${severityStyle[severity] ?? severityStyle.INFO}`}>{severity}</span>;
}

const statusStyle: Record<ScanStatus, string> = {
  PENDING: "border-blue-500/40 bg-blue-500/10 text-blue-300",
  COMPLETED: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  FAILED: "border-red-500/40 bg-red-500/10 text-red-300",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`${base} ${statusStyle[status] ?? statusStyle.PENDING}`}>{status}</span>;
}
