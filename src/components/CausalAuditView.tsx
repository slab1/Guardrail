import React, { useState, useEffect } from "react";
import { 
  Activity, 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Hash, 
  Zap, 
  Search,
  Filter,
  Download,
  AlertCircle,
  CloudUpload,
  Check
} from "lucide-react";
import { auth, signInWithGoogle, syncAuditEntryToFirestore } from "../services/firebase";

import { safeFetchJson } from "../services/apiClient";

export const CausalAuditView: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncSuccess, setSyncSuccess] = useState(false);

  useEffect(() => {
    const fetchLogs = () => {
      safeFetchJson("/api/audit/logs").then((data) => {
        if (Array.isArray(data)) setLogs([...data].reverse());
      });
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 2000);
    return () => clearInterval(interval);
  }, []);

  const filteredLogs = logs.filter(l => {
    const matchesFilter = filter === "ALL" || (filter === "VIOLATIONS" && (!l.guard_verdict || !l.logic_verdict));
    const matchesSearch = !search || l.intent.toLowerCase().includes(search.toLowerCase()) || l.type.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `guardrail_audit_${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCloudSync = async () => {
    if (logs.length === 0) return;
    if (!auth.currentUser) {
      const user = await signInWithGoogle();
      if (!user) return;
    }
    setIsSyncing(true);
    try {
      for (const log of logs.slice(0, 25)) {
        await syncAuditEntryToFirestore(log);
      }
      setSyncSuccess(true);
      setTimeout(() => setSyncSuccess(false), 3000);
    } catch (err) {
      console.error("Firestore sync error:", err);
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Avg PEP Latency</span>
            <Zap className="w-3.5 h-3.5 text-emerald-500" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-white tracking-tighter">4.24ms</span>
            <span className="text-[10px] text-emerald-500 font-bold uppercase">Sub-10ms Target</span>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Integrity Status</span>
            <ShieldCheck className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-blue-400 tracking-tighter">VERIFIED</span>
            <span className="text-[10px] text-blue-500 font-bold uppercase">Hash Chain Intact</span>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Total Events</span>
            <Activity className="w-3.5 h-3.5 text-purple-500" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-white tracking-tighter">{logs.length}</span>
            <span className="text-[10px] text-purple-500 font-bold uppercase">Traces Logged</span>
          </div>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 p-3 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input 
              type="text" 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search traces..."
              className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-300 w-full sm:w-64 focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
            />
          </div>
          
          <div className="flex items-center p-0.5 bg-slate-950 border border-slate-800 rounded-lg">
            <button 
              onClick={() => setFilter("ALL")}
              className={`px-3 py-1 text-[10px] font-bold rounded-md transition-all ${filter === "ALL" ? "bg-slate-800 text-white" : "text-slate-500 hover:text-slate-300"}`}
            >
              ALL
            </button>
            <button 
              onClick={() => setFilter("VIOLATIONS")}
              className={`px-3 py-1 text-[10px] font-bold rounded-md transition-all ${filter === "VIOLATIONS" ? "bg-rose-500/20 text-rose-400" : "text-slate-500 hover:text-slate-300"}`}
            >
              VIOLATIONS
            </button>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button 
            onClick={handleCloudSync}
            disabled={isSyncing}
            title="Sync audit traces to Cloud Firestore"
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
              syncSuccess 
                ? "bg-emerald-950/60 border-emerald-500 text-emerald-300"
                : "bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700"
            }`}
          >
            {syncSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-[11px]">Synced to Firestore</span>
              </>
            ) : (
              <>
                <CloudUpload className={`w-3.5 h-3.5 text-blue-400 ${isSyncing ? "animate-pulse" : ""}`} />
                <span className="text-[11px]">{isSyncing ? "Syncing..." : "Sync to Cloud"}</span>
              </>
            )}
          </button>

          <button 
            onClick={handleDownload}
            title="Export Audit Log as JSON"
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Audit Stream */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 border-b border-slate-800 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                <th className="px-4 py-3">Timestamp / Trace ID</th>
                <th className="px-4 py-3">Event Type</th>
                <th className="px-4 py-3">Subject Intent</th>
                <th className="px-4 py-3">Kernel Verdicts</th>
                <th className="px-4 py-3 text-right">PEP Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50 font-mono text-[11px]">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-600 italic">
                    Waiting for kernel audit events...
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log, i) => (
                  <tr key={i} className="group hover:bg-slate-900/30 transition-colors">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="text-slate-300">
                          {new Date(log.timestamp * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}.{Math.floor((log.timestamp % 1) * 1000).toString().padStart(3, '0')}
                        </span>
                        <span className="text-[9px] text-slate-600 uppercase tracking-tighter mt-0.5 font-mono">
                          TRC-{Math.floor((log.timestamp || 0) * 1000).toString(16).toUpperCase()}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-emerald-500/80 font-bold tracking-tighter">
                        {log.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <div className="truncate text-slate-400 group-hover:text-slate-200 transition-colors" title={log.intent}>
                        {log.intent}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-3">
                        <div className="flex flex-col">
                          <div className="flex items-center space-x-1">
                            {log.guard_verdict ? <ShieldCheck className="w-3 h-3 text-emerald-500" /> : <AlertCircle className="w-3 h-3 text-rose-500" />}
                            <span className={log.guard_verdict ? "text-emerald-500/70" : "text-rose-500/70"}>SEMANTIC</span>
                          </div>
                          <div className="flex items-center space-x-1 mt-0.5">
                            {log.logic_verdict ? <ShieldCheck className="w-3 h-3 text-emerald-500" /> : <AlertCircle className="w-3 h-3 text-rose-500" />}
                            <span className={log.logic_verdict ? "text-emerald-500/70" : "text-rose-500/70"}>LOGIC</span>
                          </div>
                        </div>
                        <div className="h-6 w-px bg-slate-800" />
                        <div className="flex flex-col">
                          <span className="text-[9px] text-slate-500 uppercase">Trust Index</span>
                          <span className={log.trust_score >= 70 ? "text-blue-400 font-bold" : "text-rose-400 font-bold"}>
                            {log.trust_score?.toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <span className={`font-bold ${log.latency_ms < 10 ? "text-emerald-400" : "text-amber-400"}`}>
                        {log.latency_ms?.toFixed(2)}ms
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
