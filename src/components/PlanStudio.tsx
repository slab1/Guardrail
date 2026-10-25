import React, { useState } from "react";
import {
  AutonomyLevel,
  AUTONOMY_LEVEL_NAMES,
  PlanExecutionRun,
  ValidatedPlan,
} from "../types/guardrail";
import { AGENT_SCENARIOS, AgentScenarioPreset } from "../services/agentRunner";
import { compileAndValidatePlan } from "../services/planCompiler";
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Key,
  ShieldAlert,
  ArrowRight,
  Terminal,
  FileCode,
  Sparkles,
  RefreshCw,
  Clock,
  Layers,
} from "lucide-react";

interface PlanStudioProps {
  currentPlan: ValidatedPlan | null;
  setCurrentPlan: (plan: ValidatedPlan | null) => void;
  autonomyLevel: AutonomyLevel;
  setAutonomyLevel: (lvl: AutonomyLevel) => void;
  onExecutePlan: (plan: ValidatedPlan) => void;
  executionRun: PlanExecutionRun | null;
  onInspectToken: (tokenString: string, stepId?: string) => void;
  onExplainDenial: (plan: ValidatedPlan, stepId?: string) => void;
}

export const PlanStudio: React.FC<PlanStudioProps> = ({
  currentPlan,
  setCurrentPlan,
  autonomyLevel,
  setAutonomyLevel,
  onExecutePlan,
  executionRun,
  onInspectToken,
  onExplainDenial,
}) => {
  const [intentInput, setIntentInput] = useState<string>(
    AGENT_SCENARIOS[0].intent
  );
  const [selectedAgentClass, setSelectedAgentClass] = useState<string>("coding");
  const [isCompiling, setIsCompiling] = useState<boolean>(false);

  const handleSelectScenario = (scenario: AgentScenarioPreset) => {
    setIntentInput(scenario.intent);
    setSelectedAgentClass(scenario.agentClass);
    setAutonomyLevel(scenario.defaultAutonomy);
  };

  const handleCompile = async () => {
    setIsCompiling(true);
    try {
      const plan = await compileAndValidatePlan(
        intentInput,
        selectedAgentClass,
        "operator_01",
        autonomyLevel
      );
      setCurrentPlan(plan);
    } finally {
      setIsCompiling(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Quick Scenario Presets */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Reference Agent Scenarios
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Click to load intent &amp; configure autonomy
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {AGENT_SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              onClick={() => handleSelectScenario(sc)}
              className="text-left p-3 rounded-lg border border-slate-800 bg-slate-950/60 hover:bg-slate-800/60 hover:border-blue-500/50 transition-all group"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-slate-200 group-hover:text-blue-400 transition-colors">
                  {sc.title}
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-mono uppercase font-semibold ${
                    sc.riskCategory === "Safe"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : sc.riskCategory === "Elevated"
                      ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                  }`}
                >
                  {sc.riskCategory}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-2">
                {sc.description}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Compiler Input Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-base font-semibold text-white mb-4 flex items-center justify-between">
          <span>Agent Intent Specification</span>
          <span className="text-xs font-mono text-slate-400 font-normal">
            Converts natural language into static, verifiable steps
          </span>
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Natural Language Intent
            </label>
            <textarea
              value={intentInput}
              onChange={(e) => setIntentInput(e.target.value)}
              rows={3}
              className="w-full bg-slate-950 border border-slate-700/80 rounded-lg p-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
              placeholder="e.g. Read /workspace/README.md, write /tmp/output.json, and run cargo test"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Agent Class
              </label>
              <select
                value={selectedAgentClass}
                onChange={(e) => setSelectedAgentClass(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="coding">Coding Agent (Refactor, test, git)</option>
                <option value="sysadmin">DevOps / Sysadmin (MicroVM, deployments)</option>
                <option value="data-analysis">Data Analyst (Query, aggregate, export)</option>
                <option value="untrusted">Untrusted Agent (Red-team simulation)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Target Autonomy Level
              </label>
              <select
                value={autonomyLevel}
                onChange={(e) => setAutonomyLevel(Number(e.target.value) as AutonomyLevel)}
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value={AutonomyLevel.L0}>L0: Read-Only (Observer)</option>
                <option value={AutonomyLevel.L1}>L1: Supervised (Rollback Enabled)</option>
                <option value={AutonomyLevel.L2}>L2: Semi-Autonomous (Execute Enabled)</option>
                <option value={AutonomyLevel.L3}>L3: Full Autonomy (Self-Governing)</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="text-xs text-slate-400 flex items-center space-x-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
              <span>
                Enforcing non-bypassable intent binding and per-step cryptographic capabilities
              </span>
            </div>
            <button
              onClick={handleCompile}
              disabled={isCompiling || !intentInput.trim()}
              className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium text-xs sm:text-sm shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${isCompiling ? "animate-spin" : ""}`} />
              <span>{isCompiling ? "Compiling..." : "Compile to Static Plan"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Plan Preview & Step DAG */}
      {currentPlan && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          {/* Plan Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-sm font-bold text-white">
                  {currentPlan.id}
                </span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                    currentPlan.risk_score === "low"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : currentPlan.risk_score === "medium"
                      ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                  }`}
                >
                  {currentPlan.risk_score} Risk
                </span>
                {currentPlan.is_valid ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    Static Validation Passed
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    Static Validation Failed
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">{currentPlan.description}</p>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => onInspectToken(currentPlan.plan_token || "", "Plan Root")}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition-colors"
              >
                <Key className="w-3.5 h-3.5 text-amber-400" />
                <span>Inspect Plan Token</span>
              </button>

              <button
                onClick={() => onExecutePlan(currentPlan)}
                disabled={executionRun?.status === "executing"}
                className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-xs sm:text-sm shadow-md transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{executionRun?.status === "executing" ? "Executing..." : "Execute with PEP"}</span>
              </button>
            </div>
          </div>

          {/* Validation Errors banner if any */}
          {currentPlan.validation_errors.length > 0 && (
            <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 space-y-1">
              <div className="flex items-center space-x-1.5 font-semibold text-rose-200">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Plan Static Violations Detected:</span>
              </div>
              <ul className="list-disc list-inside space-y-0.5 text-rose-300/90 pl-1">
                {currentPlan.validation_errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Steps Pipeline Visualizer */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-semibold uppercase tracking-wider text-slate-300">
                Compiled Execution Pipeline ({currentPlan.steps.length} Steps)
              </span>
              <span>Individual Ed25519 capabilities minted per step</span>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {currentPlan.steps.map((step, idx) => {
                const stepResult = executionRun?.step_results.find(
                  (r) => r.step_id === step.id
                );
                const isCurrent =
                  executionRun?.status === "executing" &&
                  executionRun.current_step_index === idx;

                return (
                  <div
                    key={step.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isCurrent
                        ? "border-blue-500 bg-blue-950/20 ring-1 ring-blue-500/50"
                        : stepResult?.success === false
                        ? "border-rose-800/80 bg-rose-950/20"
                        : stepResult?.success === true
                        ? "border-emerald-800/80 bg-emerald-950/20"
                        : "border-slate-800 bg-slate-950/50 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-start sm:items-center space-x-3">
                        <div
                          className={`w-7 h-7 rounded-lg flex items-center justify-center font-mono text-xs font-bold shrink-0 ${
                            stepResult?.success === true
                              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              : stepResult?.success === false
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : isCurrent
                              ? "bg-blue-500/20 text-blue-400 border border-blue-500/30 animate-pulse"
                              : "bg-slate-800 text-slate-300 border border-slate-700"
                          }`}
                        >
                          {stepResult?.success === true ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          ) : stepResult?.success === false ? (
                            <XCircle className="w-4 h-4 text-rose-400" />
                          ) : (
                            idx + 1
                          )}
                        </div>

                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-mono text-xs font-bold text-white">
                              {step.id}
                            </span>
                            <span className="text-xs text-slate-300 font-medium">
                              {step.description}
                            </span>
                          </div>
                          <div className="flex flex-wrap items-center gap-1.5 mt-1 text-[11px] text-slate-400">
                            <span className="font-mono bg-slate-800 px-1.5 py-0.5 rounded text-slate-300">
                              {step.action_type}
                            </span>
                            {step.resource && (
                              <span className="font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                                {step.resource}
                              </span>
                            )}
                            <span className="text-slate-500">•</span>
                            <span
                              className={`font-semibold ${
                                step.category === "read"
                                  ? "text-blue-400"
                                  : step.category === "write"
                                  ? "text-amber-400"
                                  : step.category === "execute"
                                  ? "text-purple-400"
                                  : "text-rose-400"
                              }`}
                            >
                              Req: L{step.required_level} ({step.category})
                            </span>
                            <span className="text-slate-500">•</span>
                            <span>{step.reversible ? "Reversible (LSFS)" : "Irreversible"}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 self-end sm:self-auto">
                        {stepResult && (
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                              stepResult.success
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                            }`}
                          >
                            {stepResult.duration_ms}ms
                          </span>
                        )}

                        <button
                          onClick={() =>
                            onInspectToken(
                              currentPlan.step_tokens[step.id] || "",
                              step.id
                            )
                          }
                          className="px-2.5 py-1 rounded border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-[11px] text-slate-300 flex items-center space-x-1"
                        >
                          <Key className="w-3 h-3 text-amber-400" />
                          <span>Token</span>
                        </button>

                        {stepResult?.success === false && (
                          <button
                            onClick={() => onExplainDenial(currentPlan, step.id)}
                            className="px-2.5 py-1 rounded border border-rose-700/80 bg-rose-950/60 hover:bg-rose-900/60 text-[11px] text-rose-300 flex items-center space-x-1"
                          >
                            <ShieldAlert className="w-3 h-3 text-rose-400" />
                            <span>Explain Deny</span>
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Step Execution Output */}
                    {stepResult && (
                      <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-xs">
                        {stepResult.success ? (
                          <div className="text-emerald-400 font-mono text-[11px] flex items-center space-x-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            <span>PEP Passed: {stepResult.output}</span>
                          </div>
                        ) : (
                          <div className="text-rose-400 font-mono text-[11px] flex items-center space-x-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                            <span>PEP Blocked: {stepResult.error}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
