import React, { useState } from "react";
import {
  AuthZENDecisionRequest,
  AuthZENDecisionResponse,
  AutonomyLevel,
  SPIFFEIdentity,
  ToolCategory,
} from "../types/guardrail";
import { defaultAuthZEN } from "../services/authzen";
import {
  Shield,
  Fingerprint,
  CheckCircle2,
  XCircle,
  Key,
  Users,
  Send,
  Plus,
  Server,
  Lock,
} from "lucide-react";

export const AuthZENView: React.FC = () => {
  const [identities, setIdentities] = useState<SPIFFEIdentity[]>(
    defaultAuthZEN.getSpiffeIdentities()
  );

  // New SPIFFE form
  const [newAgentClass, setNewAgentClass] = useState<string>("data-analysis");
  const [newSponsor, setNewSponsor] = useState<string>("secops_lead");

  // AuthZEN request state
  const [subjectSpiffe, setSubjectSpiffe] = useState<string>(
    identities[0]?.spiffe_id || ""
  );
  const [actionCategory, setActionCategory] = useState<ToolCategory>("write");
  const [actionName, setActionName] = useState<string>("file_write");
  const [resourceId, setResourceId] = useState<string>("/workspace/model_weights.bin");
  const [tokenPresent, setTokenPresent] = useState<boolean>(true);
  const [subjectAutonomy, setSubjectAutonomy] = useState<number>(1);

  const [decisionResponse, setDecisionResponse] =
    useState<AuthZENDecisionResponse | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);

  const handleEvaluate = async () => {
    setIsEvaluating(true);
    try {
      const req: AuthZENDecisionRequest = {
        subject: {
          type: "agent",
          id: subjectSpiffe,
          spiffe_id: subjectSpiffe,
          agent_class: "coding",
          autonomy_level: subjectAutonomy,
        },
        resource: {
          type: "file",
          id: resourceId,
        },
        action: {
          name: actionName,
          category: actionCategory,
        },
        context: {
          plan_id: "plan_authzen_test",
          step_id: "step_01",
          token_present: tokenPresent,
        },
      };

      const res = await defaultAuthZEN.evaluate(req);
      setDecisionResponse(res);
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleIssueIdentity = (e: React.FormEvent) => {
    e.preventDefault();
    const id = defaultAuthZEN.issueIdentity(newAgentClass, newSponsor);
    setIdentities(defaultAuthZEN.getSpiffeIdentities());
    setSubjectSpiffe(id.spiffe_id);
  };

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-base font-semibold text-white flex items-center space-x-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <span>OpenID Foundation AuthZEN PDP &amp; SPIFFE Workload Identity</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Complies with the AuthZEN standard policy decision point specification (Subject · Resource · Action · Context) and provides cryptographic SPIFFE mTLS workload attestation for autonomous agents.
        </p>
      </div>

      {/* AuthZEN Interactive Decision Engine */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Request Builder */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
            <Send className="w-3.5 h-3.5 text-blue-400" />
            <span>AuthZEN Evaluation Request</span>
          </h3>

          <div className="space-y-3">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Subject (SPIFFE Workload ID)
              </label>
              <select
                value={subjectSpiffe}
                onChange={(e) => setSubjectSpiffe(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
              >
                {identities.map((id) => (
                  <option key={id.spiffe_id} value={id.spiffe_id}>
                    {id.spiffe_id}
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Subject Autonomy Level
                </label>
                <select
                  value={subjectAutonomy}
                  onChange={(e) => setSubjectAutonomy(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
                >
                  <option value={0}>L0: Read-Only</option>
                  <option value={1}>L1: Supervised</option>
                  <option value={2}>L2: Semi-Autonomous</option>
                  <option value={3}>L3: Full Autonomy</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Action Category
                </label>
                <select
                  value={actionCategory}
                  onChange={(e) => {
                    const cat = e.target.value as ToolCategory;
                    setActionCategory(cat);
                    setActionName(
                      cat === "read"
                        ? "file_read"
                        : cat === "write"
                        ? "file_write"
                        : cat === "execute"
                        ? "shell_command"
                        : "admin_tool"
                    );
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
                >
                  <option value="read">read (Req: L0)</option>
                  <option value="write">write (Req: L1)</option>
                  <option value="execute">execute (Req: L2)</option>
                  <option value="admin">admin (Req: L3)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                Target Resource ID
              </label>
              <input
                type="text"
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
              />
            </div>

            <div className="flex items-center space-x-2 pt-1">
              <input
                type="checkbox"
                id="tokenCheck"
                checked={tokenPresent}
                onChange={(e) => setTokenPresent(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-0"
              />
              <label htmlFor="tokenCheck" className="text-xs text-slate-300">
                Signed Intent Token Attached in Context Header
              </label>
            </div>

            <button
              onClick={handleEvaluate}
              disabled={isEvaluating}
              className="w-full mt-2 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors shadow-md shadow-blue-600/20"
            >
              {isEvaluating ? "Consulting PDP..." : "Evaluate Decision (AuthZEN API)"}
            </button>
          </div>
        </div>

        {/* Decision Response */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                AuthZEN PDP Response
              </h3>
              {decisionResponse && (
                <span className="text-[10px] font-mono text-slate-400">
                  Latency: {decisionResponse.latency_ms} ms
                </span>
              )}
            </div>

            {decisionResponse ? (
              <div className="space-y-4">
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between ${
                    decisionResponse.decision === "PERMIT"
                      ? "bg-emerald-950/30 border-emerald-800 text-emerald-300"
                      : "bg-rose-950/30 border-rose-800 text-rose-300"
                  }`}
                >
                  <div className="flex items-center space-x-2 font-mono font-bold text-lg">
                    {decisionResponse.decision === "PERMIT" ? (
                      <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <XCircle className="w-6 h-6 text-rose-400" />
                    )}
                    <span>DECISION: {decisionResponse.decision}</span>
                  </div>
                  <span className="text-xs font-mono opacity-80">RFC AuthZEN-02</span>
                </div>

                <div className="space-y-2">
                  <span className="text-[11px] text-slate-400 font-semibold block">
                    Policy Rule Evaluations:
                  </span>
                  {decisionResponse.evaluations.map((evalItem, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-0.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-slate-300 font-bold">{evalItem.rule_name}</span>
                        <span
                          className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                            evalItem.passed
                              ? "bg-emerald-500/10 text-emerald-400"
                              : "bg-rose-500/10 text-rose-400"
                          }`}
                        >
                          {evalItem.passed ? "PASS" : "FAIL"}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-sans">
                        {evalItem.reason}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-slate-500">
                Click "Evaluate Decision" to test the AuthZEN PDP engine against the selected subject and resource.
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
            <span>RFC AuthZEN / WIMSE Compliance</span>
            <span className="text-blue-400 font-mono">Status: Standard Conformant</span>
          </div>
        </div>
      </div>

      {/* SPIFFE Workload Identities Registry */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Fingerprint className="w-4 h-4 text-blue-400" />
              <span>SPIFFE Agent Identity Registry</span>
            </h3>
            <p className="text-xs text-slate-400">
              Cryptographically attested agent identities issued to microVM workloads and host pods.
            </p>
          </div>
        </div>

        {/* Issue new SPIFFE */}
        <form
          onSubmit={handleIssueIdentity}
          className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row gap-3 text-xs"
        >
          <div className="flex-1">
            <label className="block text-[10px] text-slate-500 mb-1">Agent Class</label>
            <input
              type="text"
              value={newAgentClass}
              onChange={(e) => setNewAgentClass(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-slate-200 font-mono"
            />
          </div>
          <div className="flex-1">
            <label className="block text-[10px] text-slate-500 mb-1">Human Sponsor User</label>
            <input
              type="text"
              value={newSponsor}
              onChange={(e) => setNewSponsor(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-slate-200 font-mono"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium flex items-center space-x-1"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Attest New SPIFFE ID</span>
            </button>
          </div>
        </form>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {identities.map((id) => (
            <div
              key={id.spiffe_id}
              className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-blue-400 truncate">{id.spiffe_id}</span>
                <span className="text-[10px] text-slate-500">Domain: {id.trust_domain}</span>
              </div>
              <div className="text-[11px] text-slate-400 font-sans grid grid-cols-2 gap-1">
                <div>Workload: {id.workload}</div>
                <div>Sponsor: {id.sponsor_user}</div>
              </div>
              <div className="text-[10px] text-slate-500 truncate pt-1 border-t border-slate-900">
                Cert Fingerprint: {id.cert_fingerprint}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
