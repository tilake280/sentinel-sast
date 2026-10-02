import Link from "next/link";

import { AutoRefresh } from "@/components/AutoRefresh";
import { GatewayError, Shell } from "@/components/Shell";
import { StatusBadge } from "@/components/badges";
import { gatewayUrl, getScans, getStats } from "@/lib/api";
import { formatTime, shortCommit, shortRef } from "@/lib/format";

// Scan state lives in the gateway and changes between requests, so this page
// is rendered per request rather than prerendered at build time.
export const dynamic = "force-dynamic";

function StatTile({
  label,
  value,
  note,
  accent,
}: {
  label: string;
  value: number;
  note: string;
  accent: string;
}) {
  return (
    <div className="glass rounded-2xl p-6">
      <h3 className="text-slate-400 text-sm font-medium mb-2">{label}</h3>
      <p className={`text-4xl font-light ${accent}`}>{value.toLocaleString("en-US")}</p>
      <p className="mt-3 text-sm text-slate-500">{note}</p>
    </div>
  );
}

export default async function Home() {
  const [stats, scans] = await Promise.all([getStats(), getScans()]);

  if (!stats.ok || !scans.ok) {
    const message = !stats.ok ? stats.error : !scans.ok ? scans.error : "";
    return (
      <Shell>
        <GatewayError message={message} gatewayUrl={gatewayUrl} />
        {/* Keep trying: the page recovers on its own once the gateway is up. */}
        <AutoRefresh active intervalMs={5000} />
      </Shell>
    );
  }

  const totals = stats.data;
  const rows = scans.data.scans;
  const triaged = totals.escalated + totals.suppressed;

  return (
    <Shell>
      <AutoRefresh active={totals.pending > 0} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
        <StatTile
          label="Scans"
          value={totals.scans}
          accent="text-white"
          note={`${totals.completed} completed, ${totals.pending} pending, ${totals.failed} failed`}
        />
        <StatTile
          label="Findings"
          value={totals.findings}
          accent="text-white"
          note="across all completed scans"
        />
        <StatTile
          label="Escalated"
          value={totals.escalated}
          accent="text-red-400"
          note="triaged and shown for review"
        />
        <StatTile
          label="Suppressed by AI triage"
          value={totals.suppressed}
          accent="text-purple-400"
          note={
            triaged > 0
              ? `${((100 * totals.suppressed) / triaged).toFixed(1)}% of ${triaged.toLocaleString("en-US")} triaged findings` +
                (totals.untriaged > 0 ? `; ${totals.untriaged} untriaged` : "")
              : totals.untriaged > 0
                ? `${totals.untriaged} findings had no triage verdict`
                : "no findings triaged yet"
          }
        />
      </div>

      <div className="glass rounded-2xl p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold">Recent scans</h2>
          <span className="text-sm text-slate-500">
            {rows.length} shown{totals.pending > 0 ? " · refreshing while scans are pending" : ""}
          </span>
        </div>

        {rows.length === 0 ? (
          <div className="border border-slate-800 rounded-xl bg-slate-900/50 p-6 text-slate-400">
            <p className="mb-2">No scans yet.</p>
            <p className="text-sm text-slate-500">
              A scan is created when the gateway receives a signed push webhook at{" "}
              <code className="font-mono text-slate-400">POST /api/v1/webhook</code>. To produce one locally, run{" "}
              <code className="font-mono text-slate-400">scripts/e2e_webhook.py</code>.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-slate-800">
                  <th className="py-2 pr-4 font-medium">Repository</th>
                  <th className="py-2 pr-4 font-medium">Commit</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-4 font-medium text-right">Files</th>
                  <th className="py-2 pr-4 font-medium text-right">Findings</th>
                  <th className="py-2 pr-4 font-medium text-right">Escalated</th>
                  <th className="py-2 pr-4 font-medium text-right">Suppressed</th>
                  <th className="py-2 pr-4 font-medium text-right">Untriaged</th>
                  <th className="py-2 font-medium">Received</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-900 hover:bg-slate-900/40">
                    <td className="py-2 pr-4">
                      <Link href={`/scans/${encodeURIComponent(scan.id)}`} className="text-blue-300 hover:text-blue-200">
                        {scan.repository}
                      </Link>
                      {scan.ref ? <span className="text-slate-500"> · {shortRef(scan.ref)}</span> : null}
                    </td>
                    <td className="py-2 pr-4 font-mono text-slate-400">{shortCommit(scan.commit)}</td>
                    <td className="py-2 pr-4">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="py-2 pr-4 text-right text-slate-300">
                      {scan.status === "PENDING" ? scan.files_queued : scan.files_scanned}
                    </td>
                    <td className="py-2 pr-4 text-right text-slate-300">{scan.findings}</td>
                    <td className="py-2 pr-4 text-right text-red-300">{scan.escalated}</td>
                    <td className="py-2 pr-4 text-right text-purple-300">{scan.suppressed}</td>
                    <td className="py-2 pr-4 text-right text-amber-300">{scan.untriaged}</td>
                    <td className="py-2 text-slate-500 whitespace-nowrap">{formatTime(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Shell>
  );
}
