import React, { useState } from "react";
import { PolicyTemplate } from "../types/guardrail";
import {
  X,
  Play,
  CheckCircle2,
  AlertTriangle,
  Code,
  Beaker,
  Save,
  Info,
} from "lucide-react";

interface PolicyEditorModalProps {
  isOpen: boolean;
  onClose: () => void;
  template: PolicyTemplate | null;
  onSaved?: () => void;
}

export const PolicyEditorModal: React.FC<PolicyEditorModalProps> = ({
  isOpen,
  onClose,
  template,
  onSaved,
}) => {
  const [expr, setExpr] = useState(template?.expression || "");
  const [name, setName] = useState(template?.name || "");
  const [description, setDescription] = useState(template?.description || "");
  const [isSaving, setIsSaving] = useState(false);

  React.useEffect(() => {
    if (template) {
      setExpr(template.expression || "");
      setName(template.name || "");
      setDescription(template.description || "");
    } else {
      setExpr("");
      setName("");
      setDescription("");
    }
  }, [template]);

  const [testContext, setTestContext] = useState({
    action: "file_write",
    resource: "/workspace/config.json",
    autonomy: 1,
  });
  const [simResult, setSimResult] = useState<{
    allowed: boolean;
    reason: string;
    conflicts?: { rule_id: string; severity: string; description: string }[];
  } | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  if (!isOpen) return null;

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimResult(null);
    try {
      const res = await fetch("/api/policies/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy_expr: expr,
          context: testContext,
        }),
      });
      const data = await res.json();
      setSimResult(data);
    } catch (err) {
      console.error("Simulation failed:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSave = async () => {
    if (!expr.trim()) return;
    setIsSaving(true);
    try {
      const ruleId = template?.id || `custom-inv-${Math.random().toString(36).substring(7)}`;
      const ruleName = name.trim() || `Custom Invariant ${ruleId}`;
      const ruleDesc = description.trim() || "User registered VEPA DSL formal safety invariant";

      const res = await fetch("/api/policies/templates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: ruleId,
          name: ruleName,
          description: ruleDesc,
          expression: expr,
          version: "v1.0.0"
        })
      });

      if (res.ok) {
        // Log in audit trail
        await fetch("/api/audit/log", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: "POLICY_REGISTERED",
            intent: `Registered new formal invariant '${ruleName}': ${expr}`,
            guard_verdict: true,
            logic_verdict: true,
            trust_score: 100.0,
            latency_ms: 0.15
          })
        });

        onSaved?.();
        onClose();
      }
    } catch (err) {
      console.error("Save failed:", err);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20">
              <Code className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Policy Sandbox Editor</h3>
              <p className="text-[10px] text-slate-400">
                Draft and verify formal safety invariants
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-5 overflow-y-auto">
          {/* Name & Description fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Invariant Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Strict Egress Sandbox"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Description
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of invariant behavior..."
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
              />
            </div>
          </div>

          {/* Expression Editor */}
          <div className="space-y-2">
            <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
              <span>Policy Expression (VEPA DSL)</span>
              <Info className="w-3 h-3 cursor-help" />
            </label>
            <div className="relative group">
              <textarea
                value={expr}
                onChange={(e) => setExpr(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl p-4 font-mono text-xs text-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 min-h-[120px] transition-all"
                placeholder="e.g. action == 'file_write' IMPLIES resource.startswith('/tmp/')"
              />
            </div>
          </div>

          {/* Simulation Context */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-slate-950/40 p-4 rounded-xl border border-slate-800">
            <div className="space-y-3">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase flex items-center space-x-1.5">
                <Beaker className="w-3 h-3" />
                <span>Test Execution Context</span>
              </h4>
              <div className="space-y-2">
                <div>
                  <label className="text-[9px] text-slate-400 block mb-1">Action Type</label>
                  <select
                    value={testContext.action}
                    onChange={(e) => setTestContext({ ...testContext, action: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-1.5 text-[11px] text-slate-200"
                  >
                    <option value="file_read">file_read</option>
                    <option value="file_write">file_write</option>
                    <option value="network_egress">network_egress</option>
                    <option value="shell_command">shell_command</option>
                  </select>
                </div>
                <div>
                  <label className="text-[9px] text-slate-400 block mb-1">Resource Path/URI</label>
                  <input
                    type="text"
                    value={testContext.resource}
                    onChange={(e) => setTestContext({ ...testContext, resource: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-1.5 text-[11px] text-slate-200 font-mono"
                  />
                </div>
              </div>
            </div>

            {/* Sim Result */}
            <div className="flex flex-col justify-center">
              {simResult ? (
                <div className={`p-4 rounded-xl border animate-in zoom-in-95 duration-200 ${
                  simResult.allowed 
                    ? "bg-emerald-950/20 border-emerald-800/50 text-emerald-400" 
                    : "bg-rose-950/20 border-rose-800/50 text-rose-400"
                }`}>
                  <div className="flex items-center space-x-2 font-bold text-xs mb-1">
                    {simResult.allowed ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                    <span>{simResult.allowed ? "SIMULATION PASSED" : "SIMULATION BLOCKED"}</span>
                  </div>
                  <p className="text-[10px] opacity-80 leading-relaxed font-mono">
                    {simResult.reason}
                  </p>
                  
                  {simResult.conflicts && simResult.conflicts.length > 0 && (
                    <div className="mt-3 space-y-2 border-t border-rose-800/30 pt-2">
                      <h5 className="text-[9px] font-bold text-rose-300 uppercase tracking-tighter">Detected Conflicts:</h5>
                      {simResult.conflicts.map((c, i) => (
                        <div key={i} className="bg-rose-500/10 p-1.5 rounded border border-rose-500/20">
                          <div className="flex justify-between items-center text-[9px] font-bold text-rose-200">
                            <span>{c.rule_id}</span>
                            <span className="uppercase px-1 rounded bg-rose-500/20">{c.severity}</span>
                          </div>
                          <p className="text-[8px] text-rose-300/80 mt-0.5">{c.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="h-full flex items-center justify-center border border-dashed border-slate-800 rounded-xl text-slate-600 italic text-[10px]">
                  Ready to simulate
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-950/50 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg hover:bg-slate-800 text-slate-400 text-xs font-semibold transition-colors"
          >
            Cancel
          </button>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleSimulate}
              disabled={isSimulating || !expr.trim()}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors flex items-center space-x-1.5 border border-slate-700 disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${isSimulating ? "animate-spin" : ""}`} />
              <span>Simulate</span>
            </button>
            <button
              onClick={handleSave}
              disabled={isSaving || !expr.trim()}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors flex items-center space-x-1.5 shadow-lg shadow-emerald-600/20 disabled:opacity-50"
            >
              <Save className={`w-3.5 h-3.5 ${isSaving ? "animate-spin" : ""}`} />
              <span>{isSaving ? "Deploying..." : "Save & Deploy"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
