import React, { useState, useEffect } from "react";
import {
  Users,
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  RotateCcw,
  Key,
  Lock,
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Zap
} from "lucide-react";

interface TenantData {
  tenant_id: string;
  agent_id: string;
  name: string;
  autonomy_level: number;
  trust_score: number;
  allowed_actions: string[];
  blocked_actions: string[];
  active_tokens: number;
  status: "ACTIVE" | "QUARANTINED";
}

interface IncidentState {
  threat_level: string;
  quarantined_count: number;
  quarantines: Array<{
    tenant_id: string;
    agent_id: string;
    reason: string;
    quarantined_at: number;
    tokens_revoked: number;
  }>;
  pep_traps_total: number;
}

export const IncidentAndTenantsView: React.FC<{
  onAgentSwitched?: (agentId: string, level: number) => void;
}> = ({ onAgentSwitched }) => {
  const [tenants, setTenants] = useState<TenantData[]>([]);
  const [incidentState, setIncidentState] = useState<IncidentState | null>(null);
  const [selectedTenant, setSelectedTenant] = useState<string>("tenant-secops");
  const [killReason, setKillReason] = useState<string>("Detected unauthorized execution pattern & memory scan");
  const [isProcessing, setIsProcessing] = useState<boolean>(false);

  const fetchTenants = () => {
    fetch("/api/agents/tenants")
      .then((res) => res.json())
      .then((data) => setTenants(data))
      .catch((err) => console.error("Fetch tenants failed", err));
  };

  const fetchIncidents = () => {
    fetch("/api/incidents/active")
      .then((res) => res.json())
      .then((data) => setIncidentState(data))
      .catch((err) => console.error("Fetch incidents failed", err));
  };

  useEffect(() => {
    fetchTenants();
    fetchIncidents();
    const interval = setInterval(() => {
      fetchTenants();
      fetchIncidents();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleSwitchTenant = async (tenant: TenantData) => {
    setIsProcessing(true);
    try {
      const res = await fetch("/api/agents/switch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: tenant.agent_id,
          tenant_id: tenant.tenant_id,
          autonomy_level: tenant.autonomy_level
        })
      });
      if (res.ok) {
        onAgentSwitched?.(tenant.agent_id, tenant.autonomy_level);
        fetchTenants();
      }
    } catch (err) {
      console.error("Switch failed", err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleTriggerKillSwitch = async (tenantId: string, agentId: string) => {
    setIsProcessing(true);
    try {
      await fetch("/api/incidents/kill-switch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          agent_id: agentId,
          reason: killReason || "Emergency Kill-Switch requested by operator"
        })
      });
      fetchTenants();
      fetchIncidents();
    } catch (err) {
      console.error("Kill switch failed", err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRestoreTenant = async (tenantId: string, agentId: string) => {
    setIsProcessing(true);
    try {
      await fetch("/api/incidents/restore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          agent_id: agentId
        })
      });
      fetchTenants();
      fetchIncidents();
    } catch (err) {
      console.error("Restore failed", err);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Banner: Incident Status & Kill Switch Header */}
      <div className={`p-6 rounded-2xl border shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 transition-all ${
        incidentState?.threat_level === "CRITICAL_QUARANTINE"
          ? "bg-rose-950/40 border-rose-800 text-rose-200"
          : "bg-slate-900 border-slate-800 text-slate-200"
      }`}>
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className={`w-2.5 h-2.5 rounded-full ${
              incidentState?.threat_level === "CRITICAL_QUARANTINE" ? "bg-rose-500 animate-ping" : "bg-emerald-400"
            }`} />
            <span className="text-xs font-mono font-bold uppercase tracking-wider">
              System Threat Level: {incidentState?.threat_level || "CLEAR"}
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <span>Multi-Tenant Agent ACLs &amp; Emergency Containment</span>
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            Manage tenant-isolated agent personas, capability token boundaries, and execute real-time emergency kill-switch containment playbooks.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-center font-mono">
            <span className="text-[10px] text-slate-500 uppercase block">Active Traps</span>
            <span className="text-sm font-bold text-rose-400">{incidentState?.pep_traps_total || 0}</span>
          </div>
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-center font-mono">
            <span className="text-[10px] text-slate-500 uppercase block">Quarantined</span>
            <span className="text-sm font-bold text-rose-400">{incidentState?.quarantined_count || 0}</span>
          </div>
        </div>
      </div>

      {/* Grid: Multi-Tenant Agent Roster */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center space-x-2">
            <Users className="w-4 h-4 text-emerald-400" />
            <span>Tenant Agent Roster &amp; Capability Scopes</span>
          </h3>
          <span className="text-xs font-mono text-slate-500">{tenants.length} Active Tenants</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {tenants.map((tenant) => {
            const isQuarantined = tenant.status === "QUARANTINED";
            return (
              <div
                key={tenant.tenant_id}
                className={`p-5 rounded-2xl border transition-all flex flex-col justify-between space-y-4 ${
                  isQuarantined
                    ? "bg-rose-950/20 border-rose-800/80 shadow-rose-950/30"
                    : "bg-slate-900 border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">
                        {tenant.tenant_id} • Agent: {tenant.agent_id}
                      </span>
                      <h4 className="text-sm font-bold text-white mt-0.5">{tenant.name}</h4>
                    </div>

                    <span className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold uppercase ${
                      isQuarantined
                        ? "bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse"
                        : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    }`}>
                      {tenant.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                      <span className="text-[9px] text-slate-500 uppercase block">Autonomy Level</span>
                      <span className="text-slate-200 font-bold">L{tenant.autonomy_level}</span>
                    </div>
                    <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                      <span className="text-[9px] text-slate-500 uppercase block">Trust Index</span>
                      <span className={tenant.trust_score >= 70 ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                        {tenant.trust_score.toFixed(1)}%
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                      Allowed Action Envelope
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {tenant.allowed_actions.map((act) => (
                        <span key={act} className="text-[9px] font-mono bg-emerald-950/30 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-800/40">
                          +{act}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/60 flex items-center justify-between gap-2">
                  <button
                    onClick={() => handleSwitchTenant(tenant)}
                    disabled={isQuarantined || isProcessing}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded-lg text-xs font-bold transition-all border border-slate-700 flex items-center space-x-1.5"
                  >
                    <Cpu className="w-3.5 h-3.5 text-blue-400" />
                    <span>Switch Agent Context</span>
                  </button>

                  {isQuarantined ? (
                    <button
                      onClick={() => handleRestoreTenant(tenant.tenant_id, tenant.agent_id)}
                      disabled={isProcessing}
                      className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold transition-all flex items-center space-x-1"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Lift Quarantine</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleTriggerKillSwitch(tenant.tenant_id, tenant.agent_id)}
                      disabled={isProcessing}
                      className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold transition-all shadow-lg shadow-rose-600/20 flex items-center space-x-1"
                    >
                      <AlertOctagon className="w-3.5 h-3.5" />
                      <span>Kill-Switch</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Emergency Kill-Switch Playbook Configurator */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
        <h3 className="text-sm font-bold text-white flex items-center space-x-2">
          <AlertOctagon className="w-4 h-4 text-rose-400" />
          <span>Manual Emergency Containment Trigger</span>
        </h3>
        <p className="text-xs text-slate-400">
          Triggering the kill-switch immediately revokes all active Tier-2 Data Plane capability tokens, zeroes the trust score, freezes autonomy to L0, and places the target tenant into hardware quarantine.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Target Tenant</label>
            <select
              value={selectedTenant}
              onChange={(e) => setSelectedTenant(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-slate-200 font-mono"
            >
              {tenants.map((t) => (
                <option key={t.tenant_id} value={t.tenant_id}>
                  {t.name} ({t.tenant_id})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Containment Justification</label>
            <input
              type="text"
              value={killReason}
              onChange={(e) => setKillReason(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2 text-xs text-slate-200 font-mono"
            />
          </div>
        </div>

        <button
          onClick={() => {
            const t = tenants.find((x) => x.tenant_id === selectedTenant);
            if (t) handleTriggerKillSwitch(t.tenant_id, t.agent_id);
          }}
          disabled={isProcessing}
          className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-rose-600/20 flex items-center justify-center space-x-2"
        >
          <AlertOctagon className="w-4 h-4" />
          <span>EXECUTE CONTAINMENT PLAYBOOK (REVOKE ALL TOKENS)</span>
        </button>
      </div>
    </div>
  );
};
