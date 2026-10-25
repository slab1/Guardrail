import React, { useState } from "react";
import {
  AutonomyLevel,
  AUTONOMY_DESCRIPTIONS,
  AUTONOMY_LEVEL_NAMES,
  ValidatedPlan,
} from "../types/guardrail";
import { defaultConsentManager } from "../services/consentManager";
import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle,
  XCircle,
  HelpCircle,
  ToggleLeft,
  ToggleRight,
  Sliders,
  FileText,
  Lock,
  Unlock,
  AlertTriangle,
} from "lucide-react";

interface ConsentViewProps {
  currentPlan: ValidatedPlan | null;
  autonomyLevel: AutonomyLevel;
  setAutonomyLevel: (lvl: AutonomyLevel) => void;
  onExplainDenial: (plan: ValidatedPlan, stepId?: string) => void;
}

export const ConsentView: React.FC<ConsentViewProps> = ({
  currentPlan,
  autonomyLevel,
  setAutonomyLevel,
  onExplainDenial,
}) => {
  const [stepApprovals, setStepApprovals] = useState<Record<string, boolean>>({});
  const [autoApproveLowRisk, setAutoApproveLowRisk] = useState<boolean>(
    defaultConsentManager.autoApproveLowRisk
  );
  const [consentGranted, setConsentGranted] = useState<boolean>(true);
  const [decisionMessage, setDecisionMessage] = useState<string>("");

  // Initialize step approvals when plan changes
  React.useEffect(() => {
    if (currentPlan) {
      const initial: Record<string, boolean> = {};
      currentPlan.steps.forEach((s) => {
        initial[s.id] = s.risk_level !== "high"; // High risk requires manual opt-in
      });
      setStepApprovals(initial);
      setDecisionMessage("");
    }
  }, [currentPlan]);

  const toggleStep = (stepId: string) => {
    setStepApprovals((prev) => ({
      ...prev,
      [stepId]: !prev[stepId],
    }));
  };

  const handleApprovePlan = async () => {
    if (!currentPlan) return;
    defaultConsentManager.recordDecision(
      currentPlan.id,
      true,
      stepApprovals,
      "human_operator",
      "Explicit operator approval recorded via Guardrail Consent Console."
    );
    try {
      await fetch("/api/consent/decide", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan_id: currentPlan.id,
          approved: true,
          step_approvals: stepApprovals
        })
      });
    } catch (err) {
      console.error("Consent decision error:", err);
    }
    setConsentGranted(true);
    setDecisionMessage("Plan capabilities approved for execution and persisted to kernel.");
  };

  const handleDenyPlan = async () => {
    if (!currentPlan) return;
    defaultConsentManager.recordDecision(
      currentPlan.id,
      false,
      {},
      "human_operator",
      "Plan denied by operator review."
    );
    try {
      await fetch("/api/consent/decide", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan_id: currentPlan.id,
          approved: false,
          step_approvals: {}
        })
      });
    } catch (err) {
      console.error("Consent denial error:", err);
    }
    setConsentGranted(false);
    setDecisionMessage("Plan denied: tokens will be rejected at the PEP gateway.");
  };

  const handleToggleAutoApprove = () => {
    const next = !autoApproveLowRisk;
    setAutoApproveLowRisk(next);
    defaultConsentManager.autoApproveLowRisk = next;
  };

  return (
    <div className="space-y-6">
      {/* Autonomy Ladder Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Sliders className="w-5 h-5 text-blue-400" />
              <span>Graduated Autonomy Ladder (L0 - L3)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Defines permitted actuator boundaries and automated escalation gates
            </p>
          </div>
          <div className="flex items-center space-x-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="text-xs text-slate-400">Current Level:</span>
            <span className="font-mono text-xs font-bold text-blue-400">
              L{autonomyLevel}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {[AutonomyLevel.L0, AutonomyLevel.L1, AutonomyLevel.L2, AutonomyLevel.L3].map(
            (lvl) => {
              const isSelected = autonomyLevel === lvl;
              return (
                <div
                  key={lvl}
                  onClick={() => setAutonomyLevel(lvl)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? "border-blue-500 bg-blue-950/30 ring-1 ring-blue-500/50 shadow-lg shadow-blue-500/10"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-800/30"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                        isSelected
                          ? "bg-blue-500 text-white"
                          : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      LEVEL {lvl}
                    </span>
                    {isSelected && (
                      <span className="text-[10px] text-blue-400 font-semibold uppercase tracking-wider">
                        Active
                      </span>
                    )}
                  </div>
                  <h4 className="text-xs font-semibold text-white mb-1">
                    {AUTONOMY_LEVEL_NAMES[lvl].split(" - ")[1]}
                  </h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    {AUTONOMY_DESCRIPTIONS[lvl]}
                  </p>

                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-[10px] space-y-1 text-slate-400 font-mono">
                    <div className="flex justify-between">
                      <span>Read Tools:</span>
                      <span className="text-emerald-400">Allowed</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Write / Mutate:</span>
                      <span className={lvl >= 1 ? "text-emerald-400" : "text-rose-400"}>
                        {lvl >= 1 ? "LSFS Snapshot" : "Blocked"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Shell Exec:</span>
                      <span className={lvl >= 2 ? "text-emerald-400" : "text-rose-400"}>
                        {lvl >= 2 ? "MicroVM Bound" : "Blocked"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Admin Tools:</span>
                      <span className={lvl >= 3 ? "text-emerald-400" : "text-rose-400"}>
                        {lvl >= 3 ? "Continuous Audit" : "Requires HITL"}
                      </span>
                    </div>
                  </div>
                </div>
              );
            }
          )}
        </div>
      </div>

      {/* Plan-Level Consent & Granular Review */}
      {currentPlan ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
            <div>
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">
                  Plan Capability &amp; Consent Diff
                </h3>
                <span className="font-mono text-xs text-slate-400">({currentPlan.id})</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Review the blast radius, actuator permissions, and conditions before granting capability tokens.
              </p>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleToggleAutoApprove}
                className="flex items-center space-x-2 text-xs text-slate-300 hover:text-white"
              >
                <span>Auto-Approve Low Risk:</span>
                {autoApproveLowRisk ? (
                  <ToggleRight className="w-5 h-5 text-emerald-400" />
                ) : (
                  <ToggleLeft className="w-5 h-5 text-slate-500" />
                )}
              </button>
            </div>
          </div>

          {/* Blast Radius Summary */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-1">
                Overall Plan Risk
              </span>
              <span
                className={`text-xs font-mono font-bold uppercase px-2 py-0.5 rounded inline-block ${
                  currentPlan.risk_score === "low"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : currentPlan.risk_score === "medium"
                    ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                }`}
              >
                {currentPlan.risk_score} Risk
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-1">
                Actuators Requested
              </span>
              <span className="text-xs font-mono text-slate-200">
                {Array.from(new Set(currentPlan.steps.map((s) => s.category))).join(", ")}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-1">
                Target Resources Touched
              </span>
              <span className="text-xs font-mono text-slate-200 truncate block">
                {currentPlan.steps
                  .map((s) => s.resource)
                  .filter(Boolean)
                  .join(", ") || "None"}
              </span>
            </div>
          </div>

          {/* Granular Step Approvals */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Granular Step Capabilities
            </h4>
            <div className="space-y-2">
              {currentPlan.steps.map((step) => {
                const isApproved = !!stepApprovals[step.id];
                return (
                  <div
                    key={step.id}
                    className={`p-3 rounded-lg border flex items-center justify-between transition-colors ${
                      isApproved
                        ? "border-slate-800 bg-slate-950/70"
                        : "border-rose-900/40 bg-rose-950/10"
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => toggleStep(step.id)}
                        className={`w-5 h-5 rounded flex items-center justify-center border transition-colors ${
                          isApproved
                            ? "bg-blue-600 border-blue-500 text-white"
                            : "border-slate-700 bg-slate-900 text-transparent"
                        }`}
                      >
                        <CheckCircle className="w-3.5 h-3.5 fill-current" />
                      </button>

                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs font-bold text-white">
                            {step.id}
                          </span>
                          <span className="text-xs text-slate-200">
                            {step.description}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5 flex items-center space-x-2">
                          <span className="font-mono">{step.action_type}</span>
                          <span>•</span>
                          <span className="text-slate-300">{step.resource || "system"}</span>
                          <span>•</span>
                          <span
                            className={
                              step.risk_level === "high"
                                ? "text-rose-400 font-semibold"
                                : "text-slate-400"
                            }
                          >
                            Risk: {step.risk_level}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => onExplainDenial(currentPlan, step.id)}
                        className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1"
                      >
                        <HelpCircle className="w-3.5 h-3.5" />
                        <span>Policy Check</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Consent Actions */}
          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="text-xs text-slate-400">
              {decisionMessage ? (
                <span className="text-blue-400 font-medium">{decisionMessage}</span>
              ) : (
                <span>Tokens are valid for 15 minutes upon plan approval.</span>
              )}
            </div>

            <div className="flex items-center space-x-3 w-full sm:w-auto">
              <button
                onClick={handleDenyPlan}
                className="flex-1 sm:flex-initial flex items-center justify-center space-x-1.5 px-4 py-2 rounded-lg border border-rose-800 bg-rose-950/40 hover:bg-rose-900/40 text-rose-300 text-xs font-medium transition-colors"
              >
                <XCircle className="w-4 h-4" />
                <span>Deny Plan</span>
              </button>

              <button
                onClick={handleApprovePlan}
                className="flex-1 sm:flex-initial flex items-center justify-center space-x-1.5 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium shadow-md shadow-blue-600/20 transition-colors"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Approve Capabilities</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
          <Lock className="w-8 h-8 mx-auto mb-2 text-slate-600" />
          <p className="text-sm">No plan currently compiled.</p>
          <p className="text-xs text-slate-500 mt-1">
            Navigate to the Intent &amp; Plan Studio tab to compile a plan first.
          </p>
        </div>
      )}
    </div>
  );
};
