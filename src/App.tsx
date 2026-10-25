import React, { useState, useEffect } from "react";
import { Header } from "./components/Header";
import { PlanStudio } from "./components/PlanStudio";
import { CausalAuditView } from "./components/CausalAuditView";
import { FormalComplianceView } from "./components/FormalComplianceView";
import { AutopilotView } from "./components/AutopilotView";
import { PepFleetView } from "./components/PepFleetView";
import { AuthZENView } from "./components/AuthZENView";
import { ConsentView } from "./components/ConsentView";
import { DualTierArchView } from "./components/DualTierArchView";
import { IncidentAndTenantsView } from "./components/IncidentAndTenantsView";
import { ExplainDenyModal } from "./components/ExplainDenyModal";
import { TokenInspectorModal } from "./components/TokenInspectorModal";
import { AutonomyLevel, ValidatedPlan } from "./types/guardrail";
import { 
  testConnection, 
  onUserAuthStateChange, 
  signInWithGoogle, 
  logOut 
} from "./services/firebase";
import { User } from "firebase/auth";

const initialDefaultPlan: ValidatedPlan = {
  id: "plan-core-demo",
  intent: "Perform automated codebase security audit and update dependencies",
  description: "Automated security scanning & dependency verification",
  agent_class: "coding",
  user_id: "web_user",
  autonomy_level: AutonomyLevel.L1,
  steps: [
    {
      id: "step-1",
      description: "Inspect package.json and repository manifest",
      action_type: "file_read",
      resource: "/workspace/package.json",
      category: "read",
      required_level: AutonomyLevel.L0,
      reversible: true,
      risk_level: "low"
    },
    {
      id: "step-2",
      description: "Generate patched lockfile in staging buffer",
      action_type: "file_write",
      resource: "/tmp/package-lock.json",
      category: "write",
      required_level: AutonomyLevel.L1,
      reversible: true,
      risk_level: "low"
    },
    {
      id: "step-3",
      description: "Trigger Firecracker MicroVM container test build",
      action_type: "container_spawn",
      resource: "vm-fc-01",
      category: "execute",
      required_level: AutonomyLevel.L2,
      reversible: false,
      risk_level: "medium"
    }
  ],
  model_required: "gemini-1.5-flash",
  created_at: new Date().toISOString(),
  validation_errors: [],
  is_valid: true,
  step_tokens: {},
  risk_score: "medium"
};

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState("studio");
  const [dbConnected, setDbConnected] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [currentPlan, setCurrentPlan] = useState<ValidatedPlan>(initialDefaultPlan);
  const [explainModal, setExplainModal] = useState<{
    isOpen: boolean;
    plan: ValidatedPlan | null;
    stepId?: string;
  }>({ isOpen: false, plan: null });
  const [tokenModal, setTokenModal] = useState<{
    isOpen: boolean;
    tokenString: string;
    stepId?: string;
  }>({ isOpen: false, tokenString: "" });

  const [kernelState, setKernelState] = useState<any>({
    trust_score: 100,
    autonomy_level: 1,
    uptime: 0
  });

  useEffect(() => {
    // 1. Mandatory connection test to Firestore
    testConnection().then((connected) => {
      setDbConnected(connected);
    });

    // 2. Auth state observer
    const unsubscribeAuth = onUserAuthStateChange((user) => {
      setCurrentUser(user);
    });

    // 3. Periodic kernel state telemetry polling
    const fetchState = () => {
      fetch("/api/kernel/state")
        .then(res => res.json())
        .then(data => {
          if (data && typeof data === "object") {
            setKernelState(data);
          }
        })
        .catch(err => console.error("Kernel state fetch failed", err));
    };

    fetchState();
    const interval = setInterval(fetchState, 4000);
    
    return () => {
      clearInterval(interval);
      unsubscribeAuth();
    };
  }, []);

  const handleSetAutonomy = async (newLevel: AutonomyLevel) => {
    setKernelState((prev: any) => ({ ...prev, autonomy_level: newLevel }));
    try {
      await fetch("/api/kernel/autonomy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ autonomy_level: newLevel }),
      });
    } catch (e) {
      console.error("Autonomy update failed", e);
    }
  };

  const handleScoreChange = async (newScore: number) => {
    setKernelState((prev: any) => ({ ...prev, trust_score: newScore }));
    try {
      await fetch("/api/kernel/trust_reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ score: newScore }),
      });
    } catch (e) {
      console.error("Trust score sync failed", e);
    }
  };

  const handlePlanCreated = (apiPlan: any) => {
    if (!apiPlan) return;
    const steps = (apiPlan.steps || []).map((s: any, idx: number) => ({
      id: s.id || `step-${idx + 1}`,
      description: s.description || "Actuator invocation",
      action_type: s.action || "file_read",
      resource: s.resource || "/workspace/",
      category: s.action?.startsWith("file_") ? (s.action === "file_read" ? "read" : "write") : "execute",
      required_level: s.action === "file_read" ? AutonomyLevel.L0 : AutonomyLevel.L1,
      reversible: true,
      risk_level: s.risk || "low"
    }));

    const converted: ValidatedPlan = {
      id: apiPlan.plan_id || `plan_${Math.random().toString(36).substring(7)}`,
      intent: apiPlan.intent || apiPlan.description || "Agent Intent",
      description: apiPlan.description || "Generated Plan",
      agent_class: "coding",
      user_id: "web_user",
      autonomy_level: kernelState.autonomy_level || AutonomyLevel.L1,
      steps,
      model_required: "gemini-1.5-flash",
      created_at: new Date().toISOString(),
      validation_errors: apiPlan.validation_errors || [],
      is_valid: (apiPlan.validation_errors || []).length === 0 && apiPlan.status !== "blocked",
      step_tokens: {},
      risk_score: (apiPlan.validation_errors || []).length > 0 ? "high" : "low"
    };

    setCurrentPlan(converted);
  };

  const handleOpenExplainDenial = (planData: any, stepId?: string) => {
    const targetPlan: ValidatedPlan = planData?.steps ? planData : currentPlan;
    setExplainModal({
      isOpen: true,
      plan: targetPlan,
      stepId
    });
  };

  const handleOpenTokenInspector = (tokenString: string, stepId?: string) => {
    setTokenModal({
      isOpen: true,
      tokenString,
      stepId
    });
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans text-slate-200 antialiased">
      <Header 
        activeTab={activeTab} 
        setActiveTab={setActiveTab}
        trustScore={kernelState.trust_score ?? 100}
        autonomyLevel={kernelState.autonomy_level ?? 1}
        dbConnected={dbConnected}
        currentUser={currentUser}
        onSignIn={signInWithGoogle}
        onSignOut={logOut}
      />

      <main className="flex-1 max-w-[1440px] mx-auto w-full px-6 py-8">
        {activeTab === "studio" && (
          <PlanStudio 
            onPlanCreated={handlePlanCreated}
            onExplainDenial={handleOpenExplainDenial}
            onInspectToken={handleOpenTokenInspector}
            onNavigateTab={setActiveTab}
          />
        )}
        {activeTab === "dualtier" && (
          <DualTierArchView />
        )}
        {activeTab === "incidents" && (
          <IncidentAndTenantsView 
            onAgentSwitched={(agentId, level) => handleSetAutonomy(level)}
          />
        )}
        {activeTab === "pep" && (
          <PepFleetView 
            autonomyLevel={kernelState.autonomy_level ?? AutonomyLevel.L1} 
          />
        )}
        {activeTab === "authzen" && (
          <AuthZENView />
        )}
        {activeTab === "autopilot" && (
          <AutopilotView 
            onScoreChange={handleScoreChange} 
          />
        )}
        {activeTab === "consent" && (
          <ConsentView 
            currentPlan={currentPlan}
            autonomyLevel={kernelState.autonomy_level ?? AutonomyLevel.L1}
            setAutonomyLevel={handleSetAutonomy}
            onExplainDenial={handleOpenExplainDenial}
          />
        )}
        {activeTab === "audit" && (
          <CausalAuditView />
        )}
        {activeTab === "compliance" && (
          <FormalComplianceView />
        )}
      </main>

      <ExplainDenyModal
        isOpen={explainModal.isOpen}
        onClose={() => setExplainModal({ isOpen: false, plan: null })}
        plan={explainModal.plan}
        stepId={explainModal.stepId}
        onElevateAutonomy={() => {
          handleSetAutonomy(Math.min(3, (kernelState.autonomy_level || 1) + 1));
          setExplainModal({ isOpen: false, plan: null });
        }}
      />

      <TokenInspectorModal
        isOpen={tokenModal.isOpen}
        onClose={() => setTokenModal({ isOpen: false, tokenString: "" })}
        tokenString={tokenModal.tokenString}
        stepId={tokenModal.stepId}
      />
      
      <footer className="border-t border-slate-800/50 py-6 bg-slate-950/50 mt-auto">
        <div className="max-w-[1440px] mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center space-x-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
            <span>© 2026 Guardrail OS Kernel</span>
            <span className="text-slate-800">|</span>
            <span>Sub-10ms PEP Standard</span>
            <span className="text-slate-800">|</span>
            <span className="text-emerald-500">IETF AuthZEN & SPIFFE Standard</span>
          </div>
          <div className="flex items-center space-x-6 text-[10px] font-mono text-slate-600">
            <div className="flex items-center space-x-2">
              <span className="w-1 h-1 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>UPTIME: {kernelState.uptime ? Math.floor(kernelState.uptime % 3600).toString().padStart(4, '0') : "0000"}s</span>
            </div>
            <span>REGION: EU-WEST-1</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
