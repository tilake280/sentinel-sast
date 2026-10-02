import Link from "next/link";
import { notFound } from "next/navigation";

import { AutoRefresh } from "@/components/AutoRefresh";
import { GatewayError, Shell } from "@/components/Shell";
import { SeverityBadge, StatusBadge, VerdictBadge } from "@/components/badges";
import { gatewayUrl, getScan, type Finding, type Verdict } from "@/lib/api";
import { formatSimilarity, formatTime, shortCommit, shortRef } from "@/lib/format";

export const dynamic = "force-dynamic";

const VERDICTS: Verdict[] = ["ESCALATED", "SUPPRESSED", "UNTRIAGED"];

function isVerdict(value: string | undefined): value is Verdict {
  return value !== undefined && (VERDICTS as string[]).includes(value);
}

function FindingCard({ finding }: { finding: Finding }) {
  const trace = finding.trace ?? [];

  return (
    <li className="border border-slate-800 rounded-xl bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <VerdictBadge verdict={finding.verdict} />
        <SeverityBadge severity={finding.severity} />
        <span className="font-semibold">{finding.vulnerability}</span>
        {finding.cwe ? <span className="text-slate-500 text-sm">{finding.cwe}</span> : null}
        <span className="text-slate-500 text-sm">confidence {finding.confidence.toLowerCase()}</span>
      </div>

      <p className="font-mono text-sm text-slate-400 mb-2">
        {finding.file}:{finding.line}
        {finding.function ? <span className="text-slate-600"> in {finding.function}()</span> : null}
      </p>

      {finding.snippet ? (
        <pre className="font-mono text-sm bg-slate-950 border border-slate-800 rounded-lg p-3 overflow-x-auto text-slate-200 mb-3">
          {finding.snippet}
        </pre>
      ) : null}

      {/* Why the triage layer decided what it did, in its own words. */}
      <p className="text-sm text-slate-300">
        <span className="text-slate-500">Triage: </span>
        {finding.triage_reason || "no reason recorded"}
        {finding.verdict !== "UNTRIAGED" ? (
          <span className="text-slate-500">
            {" "}
            (similarity to nearest dismissed finding: {formatSimilarity(finding.triage_confidence)})
          </span>
        ) : null}
      </p>

      {trace.length > 0 || finding.message || finding.remediation ? (
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer text-slate-500 hover:text-slate-300">
            Details{trace.length > 1 ? ` · taint path, ${trace.length} steps` : ""}
          </summary>
          {finding.message ? <p className="mt-2 text-slate-300">{finding.message}</p> : null}
          {trace.length > 0 ? (
            <ol className="mt-2 space-y-1 font-mono text-xs text-slate-400">
              {trace.map((step, index) => (
                <li key={index}>
                  <span className="text-slate-600">line {step.line}:</span> {step.description}
                </li>
              ))}
            </ol>
          ) : null}
          {finding.remediation ? (
            <p className="mt-2 text-slate-400">
              <span className="text-slate-500">Fix: </span>
              {finding.remediation}
            </p>
          ) : null}
        </details>
      ) : null}
    </li>
  );
}

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const { id } = await params;
  const query = await searchParams;
  const requested = Array.isArray(query.verdict) ? query.verdict[0] : query.verdict;
  const filter = isVerdict(requested) ? requested : null;

  const result = await getScan(id);
  if (!result.ok) {
    if (result.status === 404) notFound();
    return (
      <Shell>
        <GatewayError message={result.error} gatewayUrl={gatewayUrl} />
        <AutoRefresh active intervalMs={5000} />
      </Shell>
    );
  }

  const { scan, findings } = result.data;
  const shown = filter ? findings.filter((finding) => finding.verdict === filter) : findings;
  const base = `/scans/${encodeURIComponent(scan.id)}`;

  const counts: Record<Verdict, number> = {
    ESCALATED: scan.escalated,
    SUPPRESSED: scan.suppressed,
    UNTRIAGED: scan.untriaged,
  };

  return (
    <Shell>
      <AutoRefresh active={scan.status === "PENDING"} />

      <p className="mb-4 text-sm">
        <Link href="/" className="text-slate-400 hover:text-white">
          ← All scans
        </Link>
      </p>

      <div className="glass rounded-2xl p-6 mb-6">
        <div className="flex flex-wrap items-center gap-3 mb-3">
          <h2 className="text-xl font-semibold">{scan.repository}</h2>
          <StatusBadge status={scan.status} />
        </div>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-3 text-sm">
          <div>
            <dt className="text-slate-500">Commit</dt>
            <dd className="font-mono text-slate-300">{shortCommit(scan.commit)}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Ref</dt>
            <dd className="text-slate-300">{scan.ref ? shortRef(scan.ref) : "—"}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Received</dt>
            <dd className="text-slate-300">{formatTime(scan.created_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Completed</dt>
            <dd className="text-slate-300">{formatTime(scan.completed_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Files scanned</dt>
            <dd className="text-slate-300">
              {scan.status === "PENDING" ? `${scan.files_queued} queued` : scan.files_scanned}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Findings</dt>
            <dd className="text-slate-300">{scan.findings}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Worker</dt>
            <dd className="text-slate-300">{scan.worker_version || "—"}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Scan id</dt>
            <dd className="font-mono text-slate-400 text-xs break-all">{scan.id}</dd>
          </div>
        </dl>

        {scan.status === "PENDING" ? (
          <p className="mt-4 text-sm text-blue-300">
            Waiting for the worker. This page refreshes until the scan finishes.
          </p>
        ) : null}
        {scan.status === "FAILED" ? (
          <p className="mt-4 text-sm text-red-300" role="alert">
            The scan failed: {scan.error || "no reason was recorded"}
          </p>
        ) : null}
      </div>

      {scan.status === "COMPLETED" ? (
        <div className="glass rounded-2xl p-6">
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <h3 className="text-lg font-semibold mr-2">Findings</h3>
            <Link
              href={base}
              className={`rounded-md border px-2.5 py-1 text-sm ${
                filter === null ? "border-slate-500 text-white" : "border-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              All {scan.findings}
            </Link>
            {VERDICTS.map((verdict) => (
              <Link
                key={verdict}
                href={`${base}?verdict=${verdict}`}
                className={`rounded-md border px-2.5 py-1 text-sm ${
                  filter === verdict
                    ? "border-slate-500 text-white"
                    : "border-slate-800 text-slate-400 hover:text-white"
                }`}
              >
                {verdict.charAt(0) + verdict.slice(1).toLowerCase()} {counts[verdict]}
              </Link>
            ))}
          </div>

          {shown.length === 0 ? (
            <p className="text-slate-400">
              {findings.length === 0
                ? "No findings in the files this scan covered."
                : `No ${filter?.toLowerCase()} findings in this scan.`}
            </p>
          ) : (
            <ul className="space-y-3">
              {shown.map((finding) => (
                <FindingCard key={finding.id} finding={finding} />
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </Shell>
  );
}
