import Link from "next/link";

// The frame shared by every page: header and content width.
export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen bg-slate-950 text-white font-sans">
      <div className="max-w-7xl mx-auto p-6 md:p-8">
        <header className="flex justify-between items-center py-4 border-b border-slate-800/50 mb-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <h1 className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              Sentinel SAST
            </h1>
          </Link>
          <nav>
            <Link href="/" className="text-slate-400 hover:text-white transition-colors">
              Scans
            </Link>
          </nav>
        </header>
        {children}
      </div>
    </main>
  );
}

// Shown in place of data when the gateway cannot be reached or answers with an
// error. Deliberately not a set of placeholder numbers.
export function GatewayError({ message, gatewayUrl }: { message: string; gatewayUrl: string }) {
  return (
    <div className="glass rounded-2xl p-6 border-red-500/30" role="alert">
      <h2 className="text-lg font-semibold text-red-300 mb-2">No data from the gateway</h2>
      <p className="text-slate-300">{message}</p>
      <p className="text-slate-500 text-sm mt-3">
        The frontend reads from <code className="font-mono text-slate-400">{gatewayUrl}</code>. Start the
        gateway, or set <code className="font-mono text-slate-400">GATEWAY_URL</code> to where it is running.
      </p>
    </div>
  );
}
