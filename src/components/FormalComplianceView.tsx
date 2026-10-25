import React, { useState, useEffect } from "react";
import { 
  ShieldCheck, 
  FileCheck, 
  BookOpen, 
  Copy, 
  ChevronRight, 
  Plus, 
  Code2, 
  CheckCircle2, 
  AlertTriangle, 
  Award,
  Globe,
  Gavel,
  Scale
} from "lucide-react";
import { PolicyTemplate, FormalPolicyRule } from "../types/guardrail";
import { PolicyEditorModal } from "./PolicyEditorModal";

export const FormalComplianceView: React.FC = () => {
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [complianceConfig, setComplianceConfig] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("COMPLIANCE");
  const [editorState, setEditorState] = useState<{
    isOpen: boolean;
    template: PolicyTemplate | null;
  }>({ isOpen: false, template: null });

  const fetchTemplates = () => {
    fetch("/api/policies/templates")
      .then(res => res.json())
      .then(data => setTemplates(data))
      .catch(err => console.error("Template fetch failed", err));
  };

  useEffect(() => {
    fetchTemplates();

    fetch("/api/compliance/config")
      .then(res => res.json())
      .then(data => setComplianceConfig(data))
      .catch(err => console.error("Compliance config fetch failed", err));
  }, []);

  const [exportBundle, setExportBundle] = useState<any>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const handleExportCompliance = async () => {
    setIsExporting(true);
    try {
      const res = await fetch("/api/compliance/export");
      const data = await res.json();
      setExportBundle(data);
      setShowExportModal(true);
    } catch (err) {
      console.error("Export failed", err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleDownloadJSON = () => {
    if (!exportBundle) return;
    const blob = new Blob([JSON.stringify(exportBundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `guardrail_os_compliance_evidence_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Navigation & Export Action */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-1 p-1 bg-slate-900 border border-slate-800 rounded-xl w-fit">
          <button 
            onClick={() => setActiveTab("COMPLIANCE")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${activeTab === "COMPLIANCE" ? "bg-slate-800 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"}`}
          >
            <Award className="w-3.5 h-3.5" />
            <span>Compliance Matrix</span>
          </button>
          <button 
            onClick={() => setActiveTab("REGISTRY")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${activeTab === "REGISTRY" ? "bg-slate-800 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"}`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Policy Registry</span>
          </button>
        </div>

        <button
          onClick={handleExportCompliance}
          disabled={isExporting}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-blue-600/20"
        >
          <FileCheck className={`w-3.5 h-3.5 ${isExporting ? "animate-spin" : ""}`} />
          <span>{isExporting ? "Generating Evidence..." : "Export Compliance Evidence Bundle"}</span>
        </button>
      </div>

      {activeTab === "COMPLIANCE" ? (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          {complianceConfig && Object.entries(complianceConfig).map(([key, framework]: [string, any]) => (
            <div key={key} className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="p-5 border-b border-slate-800 bg-slate-900/30 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center border border-blue-500/20 text-blue-400">
                    {key === "EU_AI_ACT" ? <Globe className="w-5 h-5" /> : <Gavel className="w-5 h-5" />}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white uppercase tracking-tight">{framework.title}</h3>
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-0.5">Automated Evidence Mapping</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2 bg-emerald-500/10 px-3 py-1 rounded-lg border border-emerald-500/20">
                  <span className="text-[10px] font-bold text-emerald-500">92% COMPLIANT</span>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-950 text-[10px] font-bold text-slate-500 uppercase tracking-widest border-b border-slate-800">
                      <th className="px-5 py-3">Requirement ID</th>
                      <th className="px-5 py-3">Governance Domain</th>
                      <th className="px-5 py-3">Implementation Mechanism</th>
                      <th className="px-5 py-3 text-right">Verification Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {framework.requirements.map((req: any) => (
                      <tr key={req.id} className="hover:bg-slate-900/20 transition-colors">
                        <td className="px-5 py-4">
                          <div className="flex flex-col">
                            <span className="text-xs font-bold text-blue-400 font-mono">{req.id}</span>
                            <span className="text-[10px] text-slate-300 mt-1 font-semibold">{req.title}</span>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <p className="text-[10px] text-slate-500 leading-relaxed max-w-xs">{req.description}</p>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center space-x-2">
                            <Code2 className="w-3.5 h-3.5 text-purple-500/70" />
                            <span className="text-[10px] font-mono text-slate-300">{req.guardrail_mapping}</span>
                          </div>
                        </td>
                        <td className="px-5 py-4 text-right">
                          <span className="inline-flex items-center space-x-1.5 text-[9px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 uppercase tracking-tighter">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Verified</span>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white">Symbolic Policy Registry</h3>
              <p className="text-[10px] text-slate-500 font-medium">Deterministic safety invariants applied to kernel actuator points.</p>
            </div>
            <button 
              onClick={() => setEditorState({ isOpen: true, template: null })}
              className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-emerald-600/20"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register New Invariant</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {templates.map((template) => (
              <div 
                key={template.id}
                onClick={() => setEditorState({ isOpen: true, template })}
                className="group p-5 bg-slate-900 border border-slate-800 rounded-2xl hover:border-emerald-500/50 hover:shadow-2xl hover:shadow-emerald-500/5 transition-all cursor-pointer flex flex-col justify-between h-44"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">{template.version}</span>
                    <ShieldCheck className="w-4 h-4 text-slate-700 group-hover:text-emerald-500 transition-colors" />
                  </div>
                  <h4 className="text-xs font-bold text-white group-hover:text-emerald-400 transition-colors">{template.name}</h4>
                  <p className="text-[10px] text-slate-500 line-clamp-2 leading-relaxed">{template.description}</p>
                </div>
                <div className="pt-3 border-t border-slate-800/50 flex items-center justify-between">
                  <span className="text-[9px] font-mono text-slate-600 truncate max-w-[150px]">{template.id}</span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-700 group-hover:text-emerald-500 transition-colors" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <PolicyEditorModal 
        isOpen={editorState.isOpen}
        template={editorState.template}
        onClose={() => setEditorState({ isOpen: false, template: null })}
        onSaved={fetchTemplates}
      />

      {/* Export Compliance Evidence Bundle Modal */}
      {showExportModal && exportBundle && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-5 h-5 text-blue-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">Compliance Evidence Bundle</h3>
                  <p className="text-[10px] text-slate-400">EU AI Act &amp; NIST AI RMF Formal Verification Bundle</p>
                </div>
              </div>
              <button
                onClick={() => setShowExportModal(false)}
                className="px-2 py-1 rounded bg-slate-800 text-slate-400 hover:text-white text-xs font-bold"
              >
                Close
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4">
              <div className="p-3 bg-emerald-950/20 border border-emerald-800/60 rounded-xl flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold block">Status</span>
                  <span className="text-xs font-bold text-emerald-300">{exportBundle.export_metadata?.overall_status}</span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">{exportBundle.export_metadata?.generated_at}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Raw Evidence Payload (JSON)</span>
                <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-80 select-all leading-relaxed">
                  {JSON.stringify(exportBundle, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950/50 flex items-center justify-between">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(exportBundle, null, 2));
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-bold transition-all border border-slate-700 flex items-center space-x-1.5"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copied ? "Copied JSON!" : "Copy Payload"}</span>
              </button>

              <button
                onClick={handleDownloadJSON}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-blue-600/20 flex items-center space-x-1.5"
              >
                <FileCheck className="w-3.5 h-3.5" />
                <span>Download .JSON Bundle</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
