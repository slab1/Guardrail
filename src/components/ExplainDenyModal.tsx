import React from "react";
import { ValidatedPlan } from "../types/guardrail";
import { defaultConsentManager } from "../services/consentManager";
import { ShieldAlert, X, AlertTriangle, Lightbulb, CheckCircle2 } from "lucide-react";

interface ExplainDenyModalProps {
  isOpen: boolean;
  onClose: () => void;
  plan: ValidatedPlan | null;
  stepId?: string;
  onElevateAutonomy?: () => void;
}

export const ExplainDenyModal: React.FC<ExplainDenyModalProps> = ({
  isOpen,
  onClose,
  plan,
  stepId,
  onElevateAutonomy,
}) => {
  if (!isOpen || !plan) return null;

  const explanation = defaultConsentManager.explainDenial(plan, stepId);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl p-6 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-rose-500/10 border border-rose-500/20 rounded-xl">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">
                Explain Deny: Policy Enforcement Analysis
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {stepId ? `Target Step: ${stepId}` : `Plan: ${plan.id}`}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Reason */}
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-900/60 space-y-2">
          <div className="flex items-center space-x-2 text-rose-300 font-bold text-xs">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{explanation.title}</span>
          </div>
          <p className="text-xs text-rose-200/90 leading-relaxed">
            {explanation.reason}
          </p>
        </div>

        {/* Violated Policy Specification */}
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
          <span className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block">
            Violated Operating System Policy Rule
          </span>
          <div className="text-xs font-mono text-amber-400 font-semibold">
            {explanation.violatedRule}
          </div>
        </div>

        {/* Remediation Guidance */}
        <div className="p-3.5 rounded-lg bg-blue-950/30 border border-blue-900/40 space-y-1.5">
          <div className="flex items-center space-x-1.5 text-xs font-semibold text-blue-300">
            <Lightbulb className="w-4 h-4 text-blue-400" />
            <span>Recommended Remediation</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {explanation.remediation}
          </p>
        </div>

        {/* Footer Actions */}
        <div className="pt-2 border-t border-slate-800 flex items-center justify-end space-x-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors"
          >
            Dismiss
          </button>

          {onElevateAutonomy && (
            <button
              onClick={() => {
                onElevateAutonomy();
                onClose();
              }}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition-colors"
            >
              Elevate Autonomy Level
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
