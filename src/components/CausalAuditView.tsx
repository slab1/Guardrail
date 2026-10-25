import React, { useState } from "react";
import { AuditEvent, AuditEventType } from "../types/guardrail";
import { defaultCausalAudit } from "../services/causalAudit";
import {
  Activity,
  ShieldCheck,
  AlertOctagon,
  Search,
  Filter,
  Link,
  Key,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
} from "lucide-react";

export const CausalAuditView: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>(defaultCausalAudit.getEvents());
  const [filterType, setFilterType] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [verificationStatus, setVerificationStatus] = useState<{
    valid: boolean;
    tamperedIndex?: number;
    error?: string;
    verifiedCount: number;
  } | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const handleVerifyChain = async () => {
    setIsVerifying(true);
    try {
      const result = await defaultCausalAudit.verifyChainIntegrity();
      setVerificationStatus(result);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSimulateTamper = (index: number) => {
    defaultCausalAudit.tamperWithEvent(
      index,
      "FORGED_PAYLOAD: Attacker modified database credentials in audit block"
    );
    setEvents(defaultCausalAudit.getEvents());
    setVerificationStatus(null);
  };

  const filteredEvents = events.filter((evt) => {
    if (filterType !== "ALL" && evt.event_type !== filterType) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        evt.event_id.toLowerCase().includes(query) ||
        evt.causal_label.intent.toLowerCase().includes(query) ||
        evt.causal_label.plan_id.toLowerCase().includes(query) ||
        JSON.stringify(evt.details).toLowerCase().includes(query)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Integrity Verification Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Activity className="w-5 h-5 text-blue-400" />
              <span>Kernel-Level eBPF Causal Audit Chain</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographically chained SHA-256 blocks linking every low-level actuator invocation back to human intent.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleVerifyChain}
              disabled={isVerifying}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-md shadow-blue-600/20"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>{isVerifying ? "Computing Hashes..." : "Verify Chain Integrity"}</span>
            </button>
          </div>
        </div>

        {/* Verification Result Banner */}
        {verificationStatus && (
          <div
            className={`mt-4 p-3.5 rounded-lg border text-xs font-mono flex items-start space-x-3 ${
              verificationStatus.valid
                ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
                : "bg-rose-950/50 border-rose-800 text-rose-300"
            }`}
          >
            {verificationStatus.valid ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="font-bold">
                {verificationStatus.valid
                  ? `CHAIN INTEGRITY VERIFIED: All ${verificationStatus.verifiedCount} blocks intact`
                  : "TAMPER DETECTED: CRYPTOGRAPHIC HASH CHAIN COMPROMISED!"}
              </div>
              <p className="mt-0.5 text-[11px] opacity-90">
                {verificationStatus.valid
                  ? "Every block's previous_hash correctly resolves to its parent. No historical records have been modified or deleted."
                  : verificationStatus.error}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by Event ID, Plan ID, Intent, or Payload..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-300"
          >
            <option value="ALL">All Event Types</option>
            <option value={AuditEventType.PLAN_SUBMITTED}>PLAN_SUBMITTED</option>
            <option value={AuditEventType.ACTION_EXECUTED}>ACTION_EXECUTED</option>
            <option value={AuditEventType.POLICY_VIOLATION}>POLICY_VIOLATION</option>
            <option value={AuditEventType.ROLLBACK_TRIGGERED}>ROLLBACK_TRIGGERED</option>
            <option value={AuditEventType.CONSENT_DECIDED}>CONSENT_DECIDED</option>
          </select>
        </div>
      </div>

      {/* Audit Blocks Feed */}
      <div className="space-y-3">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl text-xs">
            No audit records matching criteria.
          </div>
        ) : (
          filteredEvents.map((evt, idx) => {
            const isTampered = !!evt.details._TAMPERED;
            const isSelected = selectedEvent?.event_id === evt.event_id;

            return (
              <div
                key={evt.event_id}
                className={`p-4 rounded-xl border transition-all ${
                  isTampered
                    ? "border-rose-600 bg-rose-950/20"
                    : isSelected
                    ? "border-blue-500 bg-blue-950/20 ring-1 ring-blue-500/40"
                    : "border-slate-800 bg-slate-900 hover:border-slate-700"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-white">
                      #{idx + 1} {evt.event_id}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                        evt.event_type === AuditEventType.ACTION_EXECUTED
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : evt.event_type === AuditEventType.POLICY_VIOLATION
                          ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          : evt.event_type === AuditEventType.ROLLBACK_TRIGGERED
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                      }`}
                    >
                      {evt.event_type}
                    </span>
                    {isTampered && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-600 text-white font-bold animate-pulse">
                        MODIFIED IN STORE
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-3 text-[11px] text-slate-400 font-mono">
                    <span className="flex items-center space-x-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                    </span>
                    <button
                      onClick={() => handleSimulateTamper(idx)}
                      className="text-[10px] text-slate-500 hover:text-amber-400 transition-colors"
                      title="Simulate modifying this record to test chain verification"
                    >
                      [Simulate Tamper]
                    </button>
                  </div>
                </div>

                {/* Causal Trace details */}
                <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                      Causal Attribution (Signed Intent)
                    </span>
                    <p className="text-slate-200 mt-0.5 font-medium line-clamp-1">
                      "{evt.causal_label.intent}"
                    </p>
                    <div className="text-[11px] font-mono text-slate-400 mt-1 flex items-center space-x-2">
                      <span>Plan: {evt.causal_label.plan_id}</span>
                      <span>•</span>
                      <span>Step: {evt.causal_label.step_id}</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                      Event Execution Details
                    </span>
                    <pre className="mt-0.5 p-2 bg-slate-950 rounded text-[11px] font-mono text-slate-300 truncate">
                      {JSON.stringify(evt.details)}
                    </pre>
                  </div>
                </div>

                {/* Hashes & Linkage */}
                <div className="mt-3 pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between text-[10px] font-mono text-slate-500 gap-1">
                  <div className="flex items-center space-x-1.5 truncate">
                    <Link className="w-3 h-3 text-slate-600 shrink-0" />
                    <span className="text-slate-400">Prev Hash:</span>
                    <span className="truncate">{evt.previous_hash}</span>
                  </div>
                  <div className="flex items-center space-x-1.5 truncate">
                    <span className="text-blue-400">Block Hash:</span>
                    <span className="text-slate-300 truncate">{evt.hash}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
