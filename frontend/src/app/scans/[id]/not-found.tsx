import Link from "next/link";

import { Shell } from "@/components/Shell";

export default function ScanNotFound() {
  return (
    <Shell>
      <div className="glass rounded-2xl p-6">
        <h2 className="text-lg font-semibold mb-2">Scan not found</h2>
        <p className="text-slate-400 mb-4">The gateway has no scan with that id.</p>
        <Link href="/" className="text-blue-300 hover:text-blue-200">
          ← All scans
        </Link>
      </div>
    </Shell>
  );
}
