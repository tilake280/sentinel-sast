export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-white font-sans overflow-hidden relative">
      {/* Dynamic Background Elements */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-blue-600 rounded-full mix-blend-multiply filter blur-[120px] opacity-30 animate-pulse"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-600 rounded-full mix-blend-multiply filter blur-[120px] opacity-30 animate-pulse" style={{animationDelay: '2s'}}></div>

      <div className="relative z-10 max-w-7xl mx-auto p-8">
        {/* Header */}
        <header className="flex justify-between items-center py-6 border-b border-slate-800/50 mb-12">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-[0_0_20px_rgba(59,130,246,0.5)]">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
            </div>
            <h1 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              Sentinel SAST
            </h1>
          </div>
          <nav className="flex gap-6">
            <button className="text-slate-400 hover:text-white transition-colors">Scans</button>
            <button className="text-slate-400 hover:text-white transition-colors">Rulesets</button>
            <button className="text-slate-400 hover:text-white transition-colors">Integrations</button>
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700"></div>
          </nav>
        </header>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          <div className="glass glow-effect rounded-2xl p-6 transition-transform hover:-translate-y-1">
            <h3 className="text-slate-400 text-sm font-medium mb-2">Total Scans (24h)</h3>
            <p className="text-4xl font-light text-white">1,248</p>
            <div className="mt-4 flex items-center text-emerald-400 text-sm">
              <span className="font-medium">+12%</span>
              <span className="ml-2 text-slate-500">from yesterday</span>
            </div>
          </div>
          
          <div className="glass rounded-2xl p-6 relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-red-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <h3 className="text-slate-400 text-sm font-medium mb-2">Critical Vulnerabilities</h3>
            <p className="text-4xl font-light text-red-400">24</p>
            <div className="mt-4 flex items-center text-red-400 text-sm">
              <span className="font-medium">-3</span>
              <span className="ml-2 text-slate-500">pending resolution</span>
            </div>
          </div>

          <div className="glass rounded-2xl p-6 relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <h3 className="text-slate-400 text-sm font-medium mb-2">AI Suppressed (False Positives)</h3>
            <p className="text-4xl font-light text-purple-400">892</p>
            <div className="mt-4 flex items-center text-purple-400 text-sm">
              <span className="font-medium">94.2%</span>
              <span className="ml-2 text-slate-500">accuracy rating</span>
            </div>
          </div>
        </div>

        {/* Recent Scans Area */}
        <div className="glass rounded-2xl p-6 h-96 flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold">Active Taint Analysis Pipeline</h2>
            <div className="flex items-center gap-2">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
              </span>
              <span className="text-sm text-slate-400">Worker Nodes: Online</span>
            </div>
          </div>
          
          <div className="flex-1 border border-slate-800 rounded-xl bg-slate-900/50 p-4 font-mono text-sm overflow-y-auto">
            <div className="text-slate-500 mb-2">{'// Waiting for webhook events from Go Gateway...'}</div>
            <div className="text-blue-400 animate-pulse">{'Listening on ws://localhost:3002/stream'}</div>
          </div>
        </div>
      </div>
    </main>
  );
}
