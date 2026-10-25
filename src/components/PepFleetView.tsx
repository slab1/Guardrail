import React, { useState } from "react";
import {
  AutonomyLevel,
  LSFSSnapshot,
  MicroVMState,
  NetworkRule,
  PEPType,
  TOOL_CATEGORY_MAP,
} from "../types/guardrail";
import { defaultPepFramework } from "../services/pepFramework";
import {
  Layers,
  HardDrive,
  Cpu,
  Globe,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Plus,
  ArrowRight,
  ShieldAlert,
  Server,
  FileText,
} from "lucide-react";

interface PepFleetViewProps {
  autonomyLevel: AutonomyLevel;
}

export const PepFleetView: React.FC<PepFleetViewProps> = ({ autonomyLevel }) => {
  const [activeSubTab, setActiveSubTab] = useState<"mcp" | "fs" | "exec" | "net">("mcp");

  // Filesystem and snapshots state
  const [fileSystem, setFileSystem] = useState<Record<string, string>>(
    defaultPepFramework.getFileSystem()
  );
  const [snapshots, setSnapshots] = useState<LSFSSnapshot[]>(
    defaultPepFramework.getSnapshots()
  );
  const [selectedFile, setSelectedFile] = useState<string>("/tmp/app_config.json");
  const [rollbackNotice, setRollbackNotice] = useState<string>("");

  // MicroVMs
  const [microVMs] = useState<MicroVMState[]>(defaultPepFramework.getMicroVMs());

  // Network Rules
  const [networkRules, setNetworkRules] = useState<NetworkRule[]>(
    defaultPepFramework.getNetworkRules()
  );
  const [newDomain, setNewDomain] = useState<string>("");
  const [newAction, setNewAction] = useState<"ALLOW" | "DENY" | "INJECT_SECRETS">("ALLOW");

  // Interactive PEP tester
  const [testTool, setTestTool] = useState<string>("file_write");
  const [testResource, setTestResource] = useState<string>("/tmp/app_config.json");
  const [testResult, setTestResult] = useState<any>(null);

  const handleRunPepTest = async () => {
    let type = PEPType.MCP;
    if (testTool.startsWith("file_")) type = PEPType.FS;
    else if (testTool.startsWith("shell_")) type = PEPType.EXEC;
    else if (testTool.startsWith("http_")) type = PEPType.NET;

    const res = await defaultPepFramework.enforce({
      pep_type: type,
      action: testTool.replace("file_", "").replace("http_", ""),
      resource: testResource,
      agent_id: "test-agent",
      autonomy_level: autonomyLevel,
      payload: { content: "Updated content via PEP test suite" },
    });

    setTestResult(res);
    setFileSystem(defaultPepFramework.getFileSystem());
    setSnapshots(defaultPepFramework.getSnapshots());
  };

  const handleRollback = (snapshotId: string) => {
    const res = defaultPepFramework.rollbackSnapshot(snapshotId);
    setRollbackNotice(res.message);
    setFileSystem(defaultPepFramework.getFileSystem());
    setTimeout(() => setRollbackNotice(""), 4000);
  };

  const handleAddNetworkRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    const rule: NetworkRule = {
      id: `net-${Date.now().toString(36)}`,
      pattern: newDomain.trim(),
      action: newAction,
      tls_required: true,
      description: `User-defined rule for ${newDomain.trim()}`,
    };
    defaultPepFramework.addNetworkRule(rule);
    setNetworkRules(defaultPepFramework.getNetworkRules());
    setNewDomain("");
  };

  return (
    <div className="space-y-6">
      {/* Subtab Navigation */}
      <div className="flex border-b border-slate-800 bg-slate-900 rounded-t-xl px-2 pt-2 gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab("mcp")}
          className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-semibold transition-all border-b-2 ${
            activeSubTab === "mcp"
              ? "border-blue-500 text-blue-400 bg-slate-950"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>PEP-MCP (Tool Gateway)</span>
        </button>

        <button
          onClick={() => setActiveSubTab("fs")}
          className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-semibold transition-all border-b-2 ${
            activeSubTab === "fs"
              ? "border-blue-500 text-blue-400 bg-slate-950"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <HardDrive className="w-4 h-4" />
          <span>PEP-FS (LSFS Rollback)</span>
          {snapshots.length > 0 && (
            <span className="w-4 h-4 rounded-full bg-blue-600 text-[10px] text-white flex items-center justify-center font-mono">
              {snapshots.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab("exec")}
          className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-semibold transition-all border-b-2 ${
            activeSubTab === "exec"
              ? "border-blue-500 text-blue-400 bg-slate-950"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>PEP-Exec (Firecracker MicroVMs)</span>
        </button>

        <button
          onClick={() => setActiveSubTab("net")}
          className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-semibold transition-all border-b-2 ${
            activeSubTab === "net"
              ? "border-blue-500 text-blue-400 bg-slate-950"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>PEP-Net (Egress Firewall)</span>
        </button>
      </div>

      {/* Main Tab Content */}
      <div className="bg-slate-900 border border-slate-800 rounded-b-xl p-5">
        {/* --- PEP-MCP --- */}
        {activeSubTab === "mcp" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-semibold text-white">
                Model Context Protocol (MCP) Policy Enforcement Point
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Intercepts every client-side tool invocation, categorizes action intent, and rejects unauthorized execution before payload touches host actuators.
              </p>
            </div>

            {/* Live Interactive Tester */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider block">
                Interactive Actuator Interception Sandbox
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Tool / Actuator</label>
                  <select
                    value={testTool}
                    onChange={(e) => setTestTool(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                  >
                    {Object.keys(TOOL_CATEGORY_MAP).map((tool) => (
                      <option key={tool} value={tool}>
                        {tool} ({TOOL_CATEGORY_MAP[tool]})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Target Resource</label>
                  <input
                    type="text"
                    value={testResource}
                    onChange={(e) => setTestResource(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
                  />
                </div>

                <div className="flex items-end">
                  <button
                    onClick={handleRunPepTest}
                    className="w-full py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
                  >
                    Dispatch via PEP Gateway
                  </button>
                </div>
              </div>

              {testResult && (
                <div
                  className={`p-3 rounded-lg border text-xs font-mono mt-3 ${
                    testResult.allowed
                      ? "bg-emerald-950/30 border-emerald-800/60 text-emerald-300"
                      : "bg-rose-950/30 border-rose-800/60 text-rose-300"
                  }`}
                >
                  <div className="flex items-center space-x-1.5 font-bold mb-1">
                    {testResult.allowed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    )}
                    <span>
                      {testResult.allowed ? "200 PERMITTED" : `${testResult.status_code} BLOCKED`}
                    </span>
                  </div>
                  <div>{testResult.message}</div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Reason: {testResult.decision_reason}
                  </div>
                </div>
              )}
            </div>

            {/* Tool Category Reference Table */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-2">
                Registered Tool Classification &amp; Min Autonomy
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Tool Name</th>
                      <th className="p-2.5">Category</th>
                      <th className="p-2.5">Required Autonomy</th>
                      <th className="p-2.5">Current Policy Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                    {Object.entries(TOOL_CATEGORY_MAP).map(([tool, cat]) => {
                      const req = cat === "read" ? 0 : cat === "write" ? 1 : cat === "execute" ? 2 : 3;
                      const allowed = autonomyLevel >= req;
                      return (
                        <tr key={tool} className="hover:bg-slate-800/30">
                          <td className="p-2.5 text-slate-200">{tool}</td>
                          <td className="p-2.5 uppercase text-slate-400">{cat}</td>
                          <td className="p-2.5 text-blue-400">Level {req}</td>
                          <td className="p-2.5">
                            <span
                              className={`px-1.5 py-0.5 rounded font-semibold ${
                                allowed
                                  ? "bg-emerald-500/10 text-emerald-400"
                                  : "bg-rose-500/10 text-rose-400"
                              }`}
                            >
                              {allowed ? "Allowed" : "Blocked"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* --- PEP-FS (LSFS) --- */}
        {activeSubTab === "fs" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  PEP-FS: LSFS Semantic Filesystem &amp; Time-Travel Rollback
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Protects file assets by creating atomic pre-mutation snapshots before any agent writes. Zero file loss.
                </p>
              </div>
            </div>

            {rollbackNotice && (
              <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-800 text-xs text-blue-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0" />
                <span>{rollbackNotice}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Virtual Filesystem */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                    <FileText className="w-4 h-4 text-blue-400" />
                    <span>Active Workspace Files</span>
                  </span>
                  <span className="text-[10px] text-slate-500">Live State</span>
                </div>

                <div className="space-y-2 mb-3">
                  {Object.keys(fileSystem).map((path) => (
                    <button
                      key={path}
                      onClick={() => setSelectedFile(path)}
                      className={`w-full text-left p-2 rounded-lg text-xs font-mono flex items-center justify-between transition-colors ${
                        selectedFile === path
                          ? "bg-blue-950/50 border border-blue-500/50 text-blue-300"
                          : "bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800"
                      }`}
                    >
                      <span className="truncate">{path}</span>
                      <span className="text-[10px] text-slate-500">
                        {fileSystem[path].length} B
                      </span>
                    </button>
                  ))}
                </div>

                {selectedFile && fileSystem[selectedFile] && (
                  <div className="mt-3">
                    <span className="text-[11px] text-slate-400 mb-1 block">
                      Content Preview ({selectedFile}):
                    </span>
                    <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 overflow-x-auto max-h-40">
                      {fileSystem[selectedFile]}
                    </pre>
                  </div>
                )}
              </div>

              {/* Snapshots & Rollback History */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                    <RotateCcw className="w-4 h-4 text-amber-400" />
                    <span>LSFS Snapshot Tree</span>
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {snapshots.length} Snapshots
                  </span>
                </div>

                {snapshots.length === 0 ? (
                  <div className="text-center py-8 text-xs text-slate-500">
                    No snapshots taken yet. Snapshots are created automatically before file writes.
                  </div>
                ) : (
                  <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                    {snapshots.map((snap) => (
                      <div
                        key={snap.snapshot_id}
                        className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between"
                      >
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="text-xs font-mono font-bold text-white">
                              {snap.snapshot_id}
                            </span>
                            <span className="text-[10px] text-slate-400">
                              {new Date(snap.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <span className="text-xs font-mono text-slate-300 block truncate mt-0.5">
                            {snap.path}
                          </span>
                        </div>

                        <button
                          onClick={() => handleRollback(snap.snapshot_id)}
                          className="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-600/40 text-amber-300 text-xs font-medium flex items-center space-x-1 transition-colors"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          <span>Rollback</span>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* --- PEP-EXEC --- */}
        {activeSubTab === "exec" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-semibold text-white">
                PEP-Exec: Firecracker MicroVM Hardware Sandboxes
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Every agent shell command executes inside an isolated microVM with hardware-enforced cgroups and strict Seccomp BPF filters.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {microVMs.map((vm) => (
                <div
                  key={vm.vm_id}
                  className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Server className="w-4 h-4 text-blue-400" />
                      <span className="font-mono text-xs font-bold text-white">{vm.vm_id}</span>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${
                        vm.state === "running"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 animate-pulse"
                          : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                      }`}
                    >
                      {vm.state}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-400">
                    <div>
                      <span className="text-slate-500 block text-[10px]">CPU Allocation</span>
                      <span className="text-slate-200">{vm.vcpus} vCPUs (pinned)</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Memory Limit</span>
                      <span className="text-slate-200">{vm.memory_mb} MB (cgroup)</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-slate-500 block text-[10px]">Kernel Image</span>
                      <span className="text-slate-300 truncate block">{vm.kernel_path}</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Seccomp BPF: Active</span>
                    <span className="text-emerald-400 font-medium">Egress via PEP Only</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* --- PEP-NET --- */}
        {activeSubTab === "net" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  PEP-Net: Default-Deny Outbound Egress Gateway
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Prevents data exfiltration and credential leaks. Injects signed Bearer secrets directly at proxy level.
                </p>
              </div>
            </div>

            {/* Add Rule Form */}
            <form
              onSubmit={handleAddNetworkRule}
              className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row gap-3"
            >
              <div className="flex-1">
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="e.g. api.anthropic.com or *.internal.net"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 font-mono"
                />
              </div>

              <div className="w-full sm:w-48">
                <select
                  value={newAction}
                  onChange={(e) =>
                    setNewAction(e.target.value as "ALLOW" | "DENY" | "INJECT_SECRETS")
                  }
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-slate-200"
                >
                  <option value="ALLOW">ALLOW</option>
                  <option value="INJECT_SECRETS">INJECT_SECRETS</option>
                  <option value="DENY">DENY</option>
                </select>
              </div>

              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center justify-center space-x-1.5 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Rule</span>
              </button>
            </form>

            {/* Rules Table */}
            <div className="border border-slate-800 rounded-lg overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-2.5">Pattern</th>
                    <th className="p-2.5">Action</th>
                    <th className="p-2.5">TLS Mandatory</th>
                    <th className="p-2.5">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                  {networkRules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-800/30">
                      <td className="p-2.5 font-bold text-white">{rule.pattern}</td>
                      <td className="p-2.5">
                        <span
                          className={`px-2 py-0.5 rounded font-semibold text-[10px] ${
                            rule.action === "ALLOW"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : rule.action === "INJECT_SECRETS"
                              ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                              : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}
                        >
                          {rule.action}
                        </span>
                      </td>
                      <td className="p-2.5 text-slate-300">
                        {rule.tls_required ? "Yes (v1.3)" : "No"}
                      </td>
                      <td className="p-2.5 text-slate-400 font-sans">{rule.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
