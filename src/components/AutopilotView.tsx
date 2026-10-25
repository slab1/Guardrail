import React, { useState } from "react";
import { TrustLevel, TrustProfile } from "../types/guardrail";
import { defaultAutopilot } from "../services/autopilot";
import {
  Cpu,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  Award,
  RefreshCw,
  PlusCircle,
  MinusCircle,
  RotateCcw,
  CheckCircle2,
  Clock,
} from "lucide-react";

interface AutopilotViewProps {
  onScoreChange?: (score: number) => void;
}

export const AutopilotView: React.FC<AutopilotViewProps> = ({ onScoreChange }) => {
  const [profiles, setProfiles] = useState<TrustProfile[]>(
    defaultAutopilot.getAllProfiles()
  );
  const [selectedAgentId, setSelectedAgentId] = useState<string>("agent-coding-01");

  const currentProfile =
    profiles.find((p) => p.agent_id === selectedAgentId) || profiles[0];

  const updateProfile = (updated: TrustProfile) => {
    setProfiles(defaultAutopilot.getAllProfiles());
    onScoreChange?.(updated.trust_score);
  };

  const handleSuccess = () => {
    const updated = defaultAutopilot.recordSuccess(
      currentProfile.agent_id,
      "Simulated task executed without anomalies"
    );
    updateProfile(updated);
  };

  const handleViolation = () => {
    const updated = defaultAutopilot.recordViolation(
      currentProfile.agent_id,
      "PEP gateway rejected prohibited actuator"
    );
    updateProfile(updated);
  };

  const handleRollback = () => {
    const updated = defaultAutopilot.recordRollback(currentProfile.agent_id);
    updateProfile(updated);
  };

  const handleReset = (score: number) => {
    const updated = defaultAutopilot.resetScore(currentProfile.agent_id, score);
    updateProfile(updated);
  };

  const getLevelBadge = (level: TrustLevel) => {
    switch (level) {
      case TrustLevel.LOCKED:
        return { label: "L0: LOCKED", color: "bg-rose-500/10 text-rose-400 border-rose-500/20" };
      case TrustLevel.PROTECTED:
        return { label: "L1: PROTECTED", color: "bg-amber-500/10 text-amber-400 border-amber-500/20" };
      case TrustLevel.UNRESTRICTED:
        return { label: "L2: UNRESTRICTED", color: "bg-blue-500/10 text-blue-400 border-blue-500/20" };
      case TrustLevel.AUTONOMOUS:
        return { label: "L3: AUTONOMOUS", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" };
    }
  };

  const currentLevelBadge = getLevelBadge(currentProfile.current_trust_level);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-blue-400" />
              <span>Autopilot Closed-Loop Trust Scoring</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Dynamically elevates or demotes agent autonomy on the consent ladder based on empirical, violation-free operational track records.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-400">Agent:</span>
            <select
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 font-mono"
            >
              {profiles.map((p) => (
                <option key={p.agent_id} value={p.agent_id}>
                  {p.agent_id} ({p.agent_class})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Main Stats & Score Gauge */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Trust Score Gauge Card */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">
              Live Algorithmic Trust Score
            </span>
            <div className="flex items-baseline space-x-2 mt-2">
              <span className="text-4xl font-extrabold font-mono text-white">
                {currentProfile.trust_score.toFixed(1)}
              </span>
              <span className="text-sm font-mono text-slate-500">/ 100.0</span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-slate-950 h-3 rounded-full mt-4 overflow-hidden border border-slate-800 p-0.5">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  currentProfile.trust_score >= 85
                    ? "bg-emerald-500"
                    : currentProfile.trust_score >= 60
                    ? "bg-blue-500"
                    : currentProfile.trust_score >= 30
                    ? "bg-amber-500"
                    : "bg-rose-500"
                }`}
                style={{ width: `${Math.max(2, currentProfile.trust_score)}%` }}
              />
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400">Active Classification:</span>
            <span
              className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${currentLevelBadge.color}`}
            >
              {currentLevelBadge.label}
            </span>
          </div>
        </div>

        {/* Operational Telemetry Summary */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
            Historical Incident Ledger
          </span>

          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Successful Runs</span>
              <span className="text-emerald-400 text-lg font-bold">
                {currentProfile.success_count}
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Policy Violations</span>
              <span
                className={`text-lg font-bold ${
                  currentProfile.violation_count > 0 ? "text-rose-400" : "text-slate-400"
                }`}
              >
                {currentProfile.violation_count}
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Rollback Events</span>
              <span className="text-amber-400 text-lg font-bold">
                {currentProfile.rollback_count}
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Total Invocations</span>
              <span className="text-slate-200 text-lg font-bold">
                {currentProfile.total_events}
              </span>
            </div>
          </div>

          <div className="mt-3 text-[11px] text-slate-500">
            Decay Factor: 0.98 / week if inactive
          </div>
        </div>

        {/* Interactive Event Simulator */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
            Closed-Loop Tuning &amp; Simulator
          </span>

          <div className="space-y-2">
            <button
              onClick={handleSuccess}
              className="w-full flex items-center justify-between p-2 rounded-lg bg-emerald-950/40 border border-emerald-800/60 hover:bg-emerald-900/40 text-emerald-300 text-xs transition-colors"
            >
              <span className="flex items-center space-x-1.5">
                <PlusCircle className="w-3.5 h-3.5" />
                <span>Clean Step Execution</span>
              </span>
              <span className="font-mono font-bold">+2.5 pts</span>
            </button>

            <button
              onClick={handleViolation}
              className="w-full flex items-center justify-between p-2 rounded-lg bg-rose-950/40 border border-rose-800/60 hover:bg-rose-900/40 text-rose-300 text-xs transition-colors"
            >
              <span className="flex items-center space-x-1.5">
                <MinusCircle className="w-3.5 h-3.5" />
                <span>Simulate Policy Fault</span>
              </span>
              <span className="font-mono font-bold">-15.0 pts</span>
            </button>

            <button
              onClick={handleRollback}
              className="w-full flex items-center justify-between p-2 rounded-lg bg-amber-950/40 border border-amber-800/60 hover:bg-amber-900/40 text-amber-300 text-xs transition-colors"
            >
              <span className="flex items-center space-x-1.5">
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Trigger File Rollback</span>
              </span>
              <span className="font-mono font-bold">-10.0 pts</span>
            </button>
          </div>

          <div className="mt-3 pt-2 border-t border-slate-800 flex justify-between text-[11px]">
            <button
              onClick={() => handleReset(45)}
              className="text-slate-400 hover:text-slate-200"
            >
              Reset to Base (45)
            </button>
            <button
              onClick={() => handleReset(90)}
              className="text-blue-400 hover:text-blue-300"
            >
              Elevate to Autonomous (90)
            </button>
          </div>
        </div>
      </div>

      {/* Elevation History Log */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
          <Clock className="w-4 h-4 text-blue-400" />
          <span>Dynamic Autonomy Elevation Log</span>
        </h3>

        {currentProfile.elevation_history.length === 0 ? (
          <div className="text-xs text-slate-500 py-4 text-center">
            No elevation transitions recorded yet.
          </div>
        ) : (
          <div className="space-y-2">
            {currentProfile.elevation_history.map((item, idx) => {
              const promoted = item.new_level > item.old_level;
              return (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                >
                  <div className="flex items-center space-x-3">
                    {promoted ? (
                      <TrendingUp className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <TrendingDown className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <div>
                      <span className="text-slate-200 font-medium">{item.reason}</span>
                      <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                        Transition: Level {item.old_level} &rarr; Level {item.new_level} (Score:{" "}
                        {item.score.toFixed(1)})
                      </div>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono text-slate-400">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
