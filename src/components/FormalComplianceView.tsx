import React, { useState } from "react";
import { FormalPolicyRule, ValidatedPlan } from "../types/guardrail";
import { defaultFormalVerifier, VerificationReport } from "../services/formalVerifier";
import { defaultCompliance } from "../services/complianceService";
import {
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Wrench,
  ToggleLeft,
  ToggleRight,
  Award,
  Layers,
  Code2,
} from "lucide-react";

interface FormalComplianceViewProps {
  currentPlan: ValidatedPlan | null;
}

export const FormalComplianceView: React.FC<FormalComplianceViewProps> = ({
  currentPlan,
}) => {
  const [rules, setRules] = useState<FormalPolicyRule[]>(
    defaultFormalVerifier.getRules()
  );
  const [verificationReport, setVerificationReport] =
    useState<VerificationReport | null>(null);
  const [selectedFramework, setSelectedFramework] = useState<string>("ALL");

  const complianceControls = defaultCompliance.getControls(selectedFramework);
  const scoreData = defaultCompliance.getScore(selectedFramework);

  const handleToggleRule = (ruleId: string) => {
    defaultFormalVerifier.toggleRule(ruleId);
    setRules(defaultFormalVerifier.getRules());
  };

  const handleVerifyCurrentPlan = () => {
    if (!currentPlan) return;
    const report = defaultFormalVerifier.verifyPlan(currentPlan);
    setVerificationReport(report);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-base font-semibold text-white flex items-center space-x-2">
          <FileCheck className="w-5 h-5 text-blue-400" />
          <span>Formal Verification &amp; Regulatory Compliance Scorecards</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Applies symbolic model checking to prove safety invariants before plan dispatch, and maps runtime PEP telemetry to EU AI Act, NIST AI RMF, and ISO 42001 mandates.
        </p>
      </div>

      {/* SMT Formal Verification Rules & Patch Proposer */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Code2 className="w-4 h-4 text-purple-400" />
              <span>VEPA Symbolic Policy Rules</span>
            </h3>
            <p className="text-xs text-slate-400">
              SMT-checked mathematical invariants applied to plan step sequences.
            </p>
          </div>

          <button
            onClick={handleVerifyCurrentPlan}
            disabled={!currentPlan}
            className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors flex items-center space-x-1.5"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Verify Active Plan Invariants</span>
          </button>
        </div>

        {/* Verification Report Display */}
        {verificationReport && (
          <div
            className={`p-4 rounded-xl border text-xs font-mono space-y-2 ${
              verificationReport.is_safe
                ? "bg-emerald-950/30 border-emerald-800 text-emerald-300"
                : "bg-rose-950/30 border-rose-800 text-rose-300"
            }`}
          >
            <div className="flex items-center space-x-2 font-bold text-sm">
              {verificationReport.is_safe ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-rose-400" />
              )}
              <span>
                {verificationReport.is_safe
                  ? "PROVABLY SAFE: Plan satisfies all formal invariants"
                  : `POLICY VIOLATIONS DETECTED (${verificationReport.violations.length})`}
              </span>
            </div>

            {!verificationReport.is_safe && (
              <div className="space-y-2 pt-2">
                {verificationReport.violations.map((v, i) => (
                  <div key={i} className="p-2 rounded bg-slate-950 border border-rose-900/50">
                    <div className="text-rose-200 font-bold">
                      {v.rule_name} ({v.rule_id})
                    </div>
                    <div className="text-[11px] text-slate-400">Step: {v.step_id}</div>
                    <div className="text-[11px] text-amber-300">Remediation: {v.remediation}</div>
                  </div>
                ))}

                {/* Patch Proposal */}
                {verificationReport.patch_proposal && (
                  <div className="mt-3 p-3 rounded-lg bg-purple-950/40 border border-purple-800 text-purple-200">
                    <div className="flex items-center space-x-1.5 font-bold mb-1">
                      <Wrench className="w-4 h-4 text-purple-400" />
                      <span>{verificationReport.patch_proposal.summary}</span>
                    </div>
                    <div className="space-y-1 text-[11px]">
                      {verificationReport.patch_proposal.suggested_steps.map((ps, idx) => (
                        <div key={idx} className="pl-2 border-l-2 border-purple-600">
                          Step {ps.original_step_id}: {ps.suggested_action} ({ps.reason})
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Rules List */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="font-mono font-bold text-white">{rule.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-purple-400">
                    {rule.type}
                  </span>
                </div>
                <button
                  onClick={() => handleToggleRule(rule.id)}
                  className="text-slate-400 hover:text-white"
                >
                  {rule.enabled ? (
                    <ToggleRight className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <ToggleLeft className="w-5 h-5 text-slate-600" />
                  )}
                </button>
              </div>

              <div className="font-mono text-[11px] text-slate-400 bg-slate-900 p-1.5 rounded border border-slate-850 truncate">
                {rule.expression}
              </div>

              <div className="text-[11px] text-slate-400 font-sans">
                {rule.remediation}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Regulatory Compliance Frameworks */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Award className="w-4 h-4 text-emerald-400" />
              <span>Regulatory Compliance Matrix</span>
            </h3>
            <p className="text-xs text-slate-400">
              Continuous compliance verification across EU AI Act, NIST AI RMF, ISO 42001, and SOC2.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <select
              value={selectedFramework}
              onChange={(e) => setSelectedFramework(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-300 font-mono"
            >
              <option value="ALL">All Frameworks</option>
              <option value="EU_AI_ACT">EU AI Act (2026)</option>
              <option value="NIST_AI_RMF">NIST AI RMF</option>
              <option value="ISO_42001">ISO 42001</option>
              <option value="SOC2">SOC 2 Type II</option>
            </select>

            <div className="flex items-center space-x-1.5 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg text-emerald-400 font-mono font-bold text-xs">
              <span>{scoreData.score}%</span>
              <span className="text-[10px] text-emerald-500 font-normal font-sans">
                ({scoreData.implemented}/{scoreData.total} controls)
              </span>
            </div>
          </div>
        </div>

        {/* Controls Table */}
        <div className="border border-slate-800 rounded-lg overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-2.5">Control ID</th>
                <th className="p-2.5">Title &amp; Requirement</th>
                <th className="p-2.5">Status</th>
                <th className="p-2.5">Guardrail Architecture Mapping</th>
                <th className="p-2.5">Evidence Generated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {complianceControls.map((ctrl) => (
                <tr key={ctrl.control_id} className="hover:bg-slate-800/30">
                  <td className="p-2.5 font-mono font-bold text-blue-400 whitespace-nowrap">
                    {ctrl.control_id}
                  </td>
                  <td className="p-2.5 max-w-xs">
                    <div className="font-semibold text-slate-200">{ctrl.title}</div>
                    <div className="text-[10px] text-slate-400 line-clamp-2 mt-0.5">
                      {ctrl.description}
                    </div>
                  </td>
                  <td className="p-2.5 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {ctrl.status}
                    </span>
                  </td>
                  <td className="p-2.5 text-slate-300 font-medium">
                    {ctrl.guardrail_module}
                  </td>
                  <td className="p-2.5 text-slate-400 text-[10px] max-w-xs">
                    {ctrl.evidence}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
