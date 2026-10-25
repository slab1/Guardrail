import React, { useState, useEffect } from "react";
import {
  AutonomyLevel,
  PlanExecutionRun,
  ValidatedPlan,
} from "./types/guardrail";
import { Header } from "./components/Header";
import { PlanStudio } from "./components/PlanStudio";
import { ConsentView } from "./components/ConsentView";
import { PepFleetView } from "./components/PepFleetView";
import { CausalAuditView } from "./components/CausalAuditView";
import { AutopilotView } from "./components/AutopilotView";
import { AuthZENView } from "./components/AuthZENView";
import { FormalComplianceView } from "./components/FormalComplianceView";
import { TokenInspectorModal } from "./components/TokenInspectorModal";
import { ExplainDenyModal } from "./components/ExplainDenyModal";
import { compileAndValidatePlan } from "./services/planCompiler";
import { defaultAgentRunner, AGENT_SCENARIOS } from "./services/agentRunner";
import { defaultAutopilot } from "./services/autopilot";
import { defaultConsentManager } from "./services/consentManager";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>("studio");
  const [autonomyLevel, setAutonomyLevel] = useState<AutonomyLevel>(AutonomyLevel.L1);
  const [currentPlan, setCurrentPlan] = useState<ValidatedPlan | null>(null);
  const [executionRun, setExecutionRun] = useState<PlanExecutionRun | null>(null);
  const [trustScore, setTrustScore] = useState<number>(45.0);

  // Modals
  const [tokenModal, setTokenModal] = useState<{
    isOpen: boolean;
    tokenString: string;
    stepId?: string;
  }>({
    isOpen: false,
    tokenString: "",
  });

  const [explainModal, setExplainModal] = useState<{
    isOpen: boolean;
    stepId?: string;
  }>({
    isOpen: false,
  });

  // Seed initial plan on load
  useEffect(() => {
    const init = async () => {
      const plan = await compileAndValidatePlan(
        AGENT_SCENARIOS[0].intent,
        "coding",
        "developer_01",
        AutonomyLevel.L1,
        "plan_init_001"
      );
      defaultConsentManager.createRequest(plan);
      setCurrentPlan(plan);
      const profile = defaultAutopilot.getProfile("agent-coding-01");
      setTrustScore(profile.trust_score);
    };
    init();
  }, []);

  const handleExecutePlan = async (plan: ValidatedPlan) => {
    // Ensure consent is requested / registered
    defaultConsentManager.createRequest(plan);
    const result = await defaultAgentRunner.executePlan(plan, (run) => {
      setExecutionRun({ ...run });
    });
    setExecutionRun(result);

    const profile = defaultAutopilot.getProfile(plan.agent_class);
    setTrustScore(profile.trust_score);
  };

  const handleInspectToken = (tokenString: string, stepId?: string) => {
    setTokenModal({
      isOpen: true,
      tokenString,
      stepId,
    });
  };

  const handleExplainDenial = (plan: ValidatedPlan, stepId?: string) => {
    setExplainModal({
      isOpen: true,
      stepId,
    });
  };

  const handleElevateAutonomy = () => {
    const next = Math.min(3, autonomyLevel + 1) as AutonomyLevel;
    setAutonomyLevel(next);
    if (currentPlan) {
      compileAndValidatePlan(
        currentPlan.intent,
        currentPlan.agent_class,
        currentPlan.user_id,
        next,
        currentPlan.id
      ).then((p) => {
        defaultConsentManager.createRequest(p);
        setCurrentPlan(p);
      });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* App Header & Navigation */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        trustScore={trustScore}
        autonomyLevel={autonomyLevel}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === "studio" && (
          <PlanStudio
            currentPlan={currentPlan}
            setCurrentPlan={setCurrentPlan}
            autonomyLevel={autonomyLevel}
            setAutonomyLevel={setAutonomyLevel}
            onExecutePlan={handleExecutePlan}
            executionRun={executionRun}
            onInspectToken={handleInspectToken}
            onExplainDenial={handleExplainDenial}
          />
        )}

        {activeTab === "consent" && (
          <ConsentView
            currentPlan={currentPlan}
            autonomyLevel={autonomyLevel}
            setAutonomyLevel={setAutonomyLevel}
            onExplainDenial={handleExplainDenial}
          />
        )}

        {activeTab === "pep" && (
          <PepFleetView autonomyLevel={autonomyLevel} />
        )}

        {activeTab === "audit" && (
          <CausalAuditView />
        )}

        {activeTab === "autopilot" && (
          <AutopilotView
            onScoreChange={(score) => setTrustScore(score)}
          />
        )}

        {activeTab === "authzen" && (
          <AuthZENView />
        )}

        {activeTab === "compliance" && (
          <FormalComplianceView currentPlan={currentPlan} />
        )}
      </main>

      {/* Modals */}
      <TokenInspectorModal
        isOpen={tokenModal.isOpen}
        onClose={() => setTokenModal({ isOpen: false, tokenString: "" })}
        tokenString={tokenModal.tokenString}
        stepId={tokenModal.stepId}
      />

      <ExplainDenyModal
        isOpen={explainModal.isOpen}
        onClose={() => setExplainModal({ isOpen: false })}
        plan={currentPlan}
        stepId={explainModal.stepId}
        onElevateAutonomy={handleElevateAutonomy}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-xs text-slate-500 text-center">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="font-mono text-slate-400 font-semibold">Guardrail OS</span>
            <span>•</span>
            <span>Non-Bypassable Agent Authorization &amp; Safety</span>
          </div>
          <div className="flex items-center space-x-3 text-[11px] font-mono">
            <span>AuthZEN RFC-02</span>
            <span>•</span>
            <span>SPIFFE/WIMSE</span>
            <span>•</span>
            <span>LSFS Rollback</span>
            <span>•</span>
            <span>Firecracker microVM</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
