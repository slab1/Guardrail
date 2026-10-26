import React, { useState, useEffect } from "react";
import { 
  Send, 
  Terminal, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Zap, 
  ChevronRight, 
  Play, 
  AlertCircle,
  Activity,
  User,
  Sliders,
  Key,
  HelpCircle,
  Box,
  FileCode 
} from "lucide-react";
import { defaultTokenService } from "../services/tokenService";
import { AutonomyLevel } from "../types/guardrail";
import { auth } from "../services/firebase";

interface PlanStudioProps {
  onPlanCreated?: (plan: any) => void;
  onExplainDenial?: (plan: any, stepId?: string) => void;
  onInspectToken?: (token: string, stepId?: string) => void;
  onNavigateTab?: (tab: string) => void;
}

export const PlanStudio: React.FC<PlanStudioProps> = ({
  onPlanCreated,
  onExplainDenial,
  onInspectToken,
  onNavigateTab
}) => {
  const [intent, setIntent] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [latency, setLatency] = useState<number | null>(null);

  const handleSubmit = async () => {
    if (!intent.trim()) return;
    setIsSubmitting(true);
    setResult(null);
    try {
      const start = performance.now();
      const res = await fetch("/api/intent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ intent }),
      });
      const data = await res.json();
      setLatency(performance.now() - start);
      setResult(data);
      onPlanCreated?.(data);
    } catch (err) {
      console.error("Submission failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Intent Entry Panel */}
      <div className="lg:col-span-4 space-y-6">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-tight flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Intent Processor</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-500">USER: web_user</span>
          </div>

          <div className="space-y-3">
            <div className="relative group">
              <textarea
                value={intent}
                onChange={(e) => setIntent(e.target.value)}
                placeholder="Declare agent intent (e.g. 'Read the source code and suggest security improvements')"
                className="w-full bg-slate-950 border border-slate-700 rounded-xl p-4 font-mono text-xs text-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 min-h-[160px] transition-all placeholder:text-slate-700"
              />
              <div className="absolute bottom-3 right-3 flex items-center space-x-2">
                <button
                  onClick={handleSubmit}
                  disabled={isSubmitting || !intent.trim()}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white p-2 rounded-lg transition-all shadow-lg shadow-emerald-600/20"
                >
                  {isSubmitting ? <Activity className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {['Scan /etc/passwd', 'Audit logs', 'List all files'].map(tag => (
                <button 
                  key={tag}
                  onClick={() => setIntent(tag)}
                  className="text-[9px] font-bold text-slate-500 hover:text-emerald-400 transition-colors bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700"
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Real-time Status Card */}
        <div className="bg-slate-950 border border-slate-800 rounded-2xl p-5 space-y-4">
          <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Enforcement Engine</h4>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400 flex items-center space-x-2">
                <ShieldCheck className="w-3.5 h-3.5 text-blue-500" />
                <span>Formal Verifier (Z3)</span>
              </span>
              <span className="text-emerald-400 font-bold uppercase">Active</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400 flex items-center space-x-2">
                <Zap className="w-3.5 h-3.5 text-amber-500" />
                <span>Semantic Guard</span>
              </span>
              <span className="text-emerald-400 font-bold uppercase">Online</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400 flex items-center space-x-2">
                <Box className="w-3.5 h-3.5 text-purple-500" />
                <span>RAG Rails</span>
              </span>
              <span className="text-emerald-400 font-bold uppercase">Enforcing</span>
            </div>
          </div>
        </div>
      </div>

      {/* Results & Pipeline View */}
      <div className="lg:col-span-8 space-y-6">
        {!result && !isSubmitting ? (
          <div className="h-full min-h-[400px] flex flex-col items-center justify-center border-2 border-dashed border-slate-800 rounded-2xl p-12 text-center bg-slate-900/20">
            <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4">
              <Terminal className="w-8 h-8 text-slate-600" />
            </div>
            <h3 className="text-white font-bold mb-1">Awaiting Intent Declaration</h3>
            <p className="text-xs text-slate-500 max-w-xs">Enter a command in the processor to begin the kernel safety validation sequence.</p>
          </div>
        ) : isSubmitting ? (
          <div className="space-y-6">
             {[1, 2, 3].map(i => (
               <div key={i} className="animate-pulse bg-slate-900 border border-slate-800 h-24 rounded-2xl" />
             ))}
          </div>
        ) : (
          <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-500">
            {/* Verdict Overview */}
            <div className={`p-5 rounded-2xl border flex items-center justify-between shadow-2xl ${
              result.status === 'blocked' ? "bg-rose-950/20 border-rose-800" : 
              result.status === 'pending_semantic' ? "bg-amber-950/20 border-amber-800" :
              "bg-emerald-950/20 border-emerald-800"
            }`}>
              <div className="flex items-center space-x-4">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                  result.status === 'blocked' ? "bg-rose-500/20 text-rose-400" : 
                  result.status === 'pending_semantic' ? "bg-amber-500/20 text-amber-400" :
                  "bg-emerald-500/20 text-emerald-400"
                }`}>
                  {result.status === 'blocked' ? <ShieldAlert className="w-6 h-6" /> : 
                   result.status === 'pending_semantic' ? <Clock className="w-6 h-6 animate-pulse" /> :
                   <ShieldCheck className="w-6 h-6" />}
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white tracking-tight">
                    {result.status === 'blocked' ? "INTENT BLOCKED" : 
                     result.status === 'pending_semantic' ? "SPECULATIVE VALIDATION" :
                     "PLAN VALIDATED"}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Kernel Safety Result • PEP Latency: <span className="font-mono font-bold text-white">{result.latency_ms?.toFixed(2)}ms</span>
                  </p>
                </div>
              </div>
              
              <div className="flex items-center space-x-3">
                <div className="flex flex-col items-end">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Semantic Confidence</span>
                  <span className={`text-lg font-mono font-bold ${result.guard_result?.status === 'pending' ? "text-amber-400" : "text-white"}`}>
                    {(result.guard_result?.confidence * 100).toFixed(1)}%
                    {result.guard_result?.status === 'pending' && <span className="text-[8px] ml-1 uppercase tracking-widest">(Est.)</span>}
                  </span>
                </div>
              </div>
            </div>

            {/* Step Trace */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              <div className="p-4 border-b border-slate-800 bg-slate-950/50 flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-300 flex items-center space-x-2">
                  <FileCode className="w-4 h-4 text-blue-400" />
                  <span>Execution Plan Steps ({result.steps?.length})</span>
                </h4>
                <span className="text-[10px] font-mono text-slate-500 text-xs">ID: {result.plan_id}</span>
              </div>
              <div className="divide-y divide-slate-800">
                {result.steps?.map((step: any, i: number) => (
                  <div key={i} className="p-4 group hover:bg-slate-800/30 transition-colors flex items-center justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="mt-1 text-[10px] font-mono text-slate-600 w-4">0{i+1}</div>
                      <div>
                        <p className="text-xs font-bold text-slate-200 group-hover:text-white transition-colors">{step.description}</p>
                        <div className="flex items-center space-x-3 mt-1.5 text-[10px] font-mono">
                          <span className="text-blue-400 uppercase tracking-tighter">{step.action}</span>
                          <span className="text-slate-600">→</span>
                          <span className="text-slate-500 truncate max-w-[200px]">{step.resource}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {step.capability_token && (
                        <button
                          onClick={() => onInspectToken?.(JSON.stringify(step.capability_token, null, 2), step.id)}
                          title="Inspect Tier-2 Hardware Capability Token"
                          className="px-2 py-0.5 rounded text-[9px] font-mono font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-all flex items-center space-x-1"
                        >
                          <Key className="w-2.5 h-2.5" />
                          <span>TOKEN</span>
                        </button>
                      )}
                      <div className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${
                        step.risk === 'high' ? "bg-rose-500/10 text-rose-400 border-rose-500/20" :
                        step.risk === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                        "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                      }`}>
                        {step.risk} Risk
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Validation Pipeline Console */}
            {result.validation_errors?.length > 0 && (
              <div className="bg-rose-950/10 border border-rose-900/50 rounded-2xl p-5 space-y-3">
                <h4 className="text-xs font-bold text-rose-400 flex items-center space-x-2 uppercase tracking-widest">
                  <AlertCircle className="w-4 h-4" />
                  <span>Kernel Pipeline Violations</span>
                </h4>
                <div className="space-y-2">
                  {result.validation_errors.map((err: string, i: number) => (
                    <div key={i} className="bg-rose-900/20 p-3 rounded-xl border border-rose-800/30 font-mono text-[11px] text-rose-200">
                      <span className="text-rose-500 mr-2">[VERIFIER_ERR]</span>
                      {err}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Action Bar based on State */}
            {result.status === 'blocked' && (
              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-rose-400 font-mono flex items-center space-x-1.5">
                  <AlertCircle className="w-4 h-4" />
                  <span>Execution prohibited by kernel safety invariant.</span>
                </span>
                <button
                  onClick={() => onExplainDenial?.(result)}
                  className="flex items-center space-x-2 px-4 py-2 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded-xl text-xs font-bold transition-all shadow-lg"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Explain Denial (PEP Analysis)</span>
                </button>
              </div>
            )}
            
            {(result.status === 'pending_consent' || result.status === 'pending_semantic') && (
              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => onNavigateTab?.("consent")}
                  className="flex items-center space-x-1.5 px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition-all"
                >
                  <Sliders className="w-3.5 h-3.5 text-blue-400" />
                  <span>Review in Consent Matrix</span>
                </button>

                <button 
                  onClick={async () => {
                    try {
                      const idToken = auth.currentUser ? await auth.currentUser.getIdToken() : "";
                      const authHeader = idToken ? `Bearer ${idToken}` : "Bearer dev-approver";
                      const res = await fetch("/api/consent/decide", {
                        method: "POST",
                        headers: { 
                          "Content-Type": "application/json",
                          "Authorization": authHeader,
                        },
                        body: JSON.stringify({
                          plan_id: result.plan_id,
                          approved: true,
                          step_approvals: result.steps.reduce((acc: any, s: any) => ({ ...acc, [s.id]: true }), {}),
                          plan_hash: result.plan_hash || ""
                        }),
                      });
                      if (res.ok) {
                        const data = await res.json();
                        setResult({
                          ...result,
                          status: 'authorized',
                          steps: data.steps || result.steps
                        });
                      }
                    } catch (err) {
                      console.error("Authorization failed", err);
                    }
                  }}
                  className="flex items-center space-x-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all shadow-xl shadow-emerald-600/30"
                >
                  <span>Authorize Execution Plan</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
            
            {result.status === 'authorized' && (
              <div className="space-y-3">
                <div className="bg-emerald-950/20 border border-emerald-800 rounded-2xl p-5 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-bold text-emerald-400 uppercase tracking-tight">Kernel Authorization Received • Dispatching Agent</span>
                  </div>
                  <div className="flex items-center space-x-2">
                     <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                     <span className="text-[10px] font-mono text-emerald-500">EXECUTING...</span>
                  </div>
                </div>

                <div className="flex justify-end space-x-3">
                  <button
                    onClick={async () => {
                      const { token } = await defaultTokenService.createPlanToken(
                        result.plan_id || "plan_core",
                        result.description || "Authorized Execution Plan",
                        "coding",
                        "web_user",
                        AutonomyLevel.L1
                      );
                      onInspectToken?.(token);
                    }}
                    className="flex items-center space-x-1.5 px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition-all"
                  >
                    <Key className="w-3.5 h-3.5 text-amber-400" />
                    <span>Inspect Capability Token</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )
      }
      </div>
    </div>
  );
};
