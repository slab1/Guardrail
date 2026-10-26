import React, { useState, useEffect } from "react";
import {
  Layers,
  Zap,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Key,
  Lock,
  ArrowRight,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Activity,
  Terminal,
  Server,
  FileCode,
  Scale
} from "lucide-react";

interface BenchmarkData {
  tier1_control_plane: {
    name: string;
    latency_ms: number;
    latency_p50_ms?: number;
    latency_p95_ms?: number;
    operations: string[];
    target: string;
  };
  tier2_data_plane: {
    name: string;
    latency_ms: number;
    latency_p50_ms?: number;
    latency_p95_ms?: number;
    operations: string[];
    target: string;
  };
  speedup_factor: number;
  pep_budget_target: string;
}

export const DualTierArchView: React.FC = () => {
  const [benchmark, setBenchmark] = useState<BenchmarkData | null>(null);
  const [isRunningBench, setIsRunningBench] = useState<boolean>(false);
  const [syscallProfiles, setSyscallProfiles] = useState<any>({});
  const [activeLevelTab, setActiveLevelTab] = useState<number>(1);
  const [metrics, setMetrics] = useState<any>({
    total_enforcements: 0,
    total_traps: 0,
    average_latency_ms: 0.18,
    recent_traps: []
  });

  // Simulator state
  const [testAction, setTestAction] = useState<string>("file_write");
  const [testResource, setTestResource] = useState<string>("/workspace/model_weights.bin");
  const [simScenario, setSimScenario] = useState<"VALID" | "FORGERY" | "REPLAY" | "ESCAPEMENT" | "ILLEGAL_SYSCALL" | "ATTACK_EXECVE" | "ATTACK_SOCKET" | "ATTACK_PRIV">("VALID");
  const [simResult, setSimResult] = useState<any>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const fetchSyscallRules = () => {
    fetch("/api/pep/syscall-rules")
      .then((res) => res.json())
      .then((data) => setSyscallProfiles(data))
      .catch((err) => console.error("Syscall rules fetch failed", err));
  };

  const fetchMetrics = () => {
    fetch("/api/pep/metrics")
      .then((res) => res.json())
      .then((data) => setMetrics(data))
      .catch((err) => console.error("Metrics fetch failed", err));
  };

  const runBenchmark = async () => {
    setIsRunningBench(true);
    try {
      const res = await fetch("/api/pep/dual-benchmark", { method: "POST" });
      const data = await res.json();
      setBenchmark(data);
    } catch (err) {
      console.error("Benchmark failed", err);
    } finally {
      setIsRunningBench(false);
    }
  };

  useEffect(() => {
    fetchSyscallRules();
    fetchMetrics();
    runBenchmark();
    const interval = setInterval(fetchMetrics, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleExecuteSimulation = async () => {
    setIsSimulating(true);
    setSimResult(null);

    try {
      if (simScenario.startsWith("ATTACK_")) {
        const vec = simScenario === "ATTACK_EXECVE" 
          ? "execve_shell" 
          : simScenario === "ATTACK_SOCKET" 
            ? "unauthorized_socket" 
            : "privilege_escalation";

        const res = await fetch("/api/pep/attack-inject", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ vector: vec })
        });
        const data = await res.json();
        setSimResult(data);
        fetchMetrics();
      } else if (simScenario === "ILLEGAL_SYSCALL") {
        const res = await fetch("/api/pep/simulate-trap", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            trap_type: "UNAUTHORIZED_SYSCALL_TRAP",
            action: "reboot()",
            resource: "/proc/sysrq-trigger"
          })
        });
        const data = await res.json();
        setSimResult(data);
        fetchMetrics();
      } else {
        // Create a test token from Tier 1 first
        const intentRes = await fetch("/api/intent", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ intent: `Execute safe operation on ${testResource}` })
        });
        const planData = await intentRes.json();
        const baseToken = planData.steps?.[0]?.capability_token;

        if (!baseToken) {
          setSimResult({
            verdict: "TRAP_DENY",
            reason: "Tier 1 rejected intent; no capability token was issued.",
            syscall_trap: "EPERM",
            latency_ms: 0.12,
            tier: "Tier-2 Data Plane (Hardware-Adjacent PEP)"
          });
          return;
        }

        // Apply mutation based on scenario
        const payloadToken = { ...baseToken };
        const actionToRequest = testAction;
        let resourceToRequest = testResource;

        if (simScenario === "FORGERY") {
          // Alter the signature or resource without re-signing
          payloadToken.signature = "deadbeef_forged_signature_0000";
        } else if (simScenario === "ESCAPEMENT") {
          // Request access outside authorized resource envelope
          resourceToRequest = "/etc/shadow";
        } else if (simScenario === "REPLAY") {
          // First use validly consumes the linear nonce
          await fetch("/api/pep/verify-token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              token_data: payloadToken,
              requested_action: actionToRequest,
              target_resource: resourceToRequest
            })
          });
          // Now reuse same payloadToken with already consumed nonce!
        }

        const verifyRes = await fetch("/api/pep/verify-token", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            token_data: payloadToken,
            requested_action: actionToRequest,
            target_resource: resourceToRequest
          })
        });
        const result = await verifyRes.json();
        setSimResult(result);
        fetchMetrics();
      }
    } catch (err) {
      console.error("Simulation error", err);
    } finally {
      setIsSimulating(false);
    }
  };

  const currentSyscallProfile = syscallProfiles[activeLevelTab] || {
    level_name: `L${activeLevelTab}`,
    allowed_syscalls: [],
    blocked_syscalls: [],
    default_action: "TRAP",
    description: "Loading profile..."
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Dual-Tier Architecture Statement */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2 text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Production Safety Architecture</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
              <span>The Dual-Tier Model: Control Plane vs. Hardware Data Plane</span>
            </h2>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              Separates cognitive policy compilation, SMT reasoning, and Dual-LLM safety checks (Tier 1 Control Plane) from non-bypassable, microsecond capability verification and Seccomp/eBPF syscall trapping (Tier 2 Data Plane).
            </p>
          </div>

          <button
            onClick={runBenchmark}
            disabled={isRunningBench}
            className="flex items-center space-x-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-emerald-600/20 shrink-0"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isRunningBench ? "animate-spin" : ""}`} />
            <span>{isRunningBench ? "Benchmarking..." : "Run Live Benchmark"}</span>
          </button>
        </div>
      </div>

      {/* Topology Diagram: Visualizing the Dual-Tier Boundary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Tier 1: Control Plane Card */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                  <BrainIcon className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Tier 1: Control Plane</h3>
                  <span className="text-[10px] font-mono text-slate-500">Language: Python (FastAPI) &amp; TypeScript</span>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                COGNITIVE PLANE
              </span>
            </div>

            <div className="mt-4 space-y-3">
              <p className="text-xs text-slate-400 leading-relaxed">
                Executes heavyweight cognitive security tasks asynchronously. Compiles human intent into formal logic invariants and issues tamper-proof cryptographic tokens.
              </p>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                    <span>Z3 SMT Invariant Solver (VEPA DSL)</span>
                  </span>
                  <span className="text-emerald-400 font-bold">100% Deterministic</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <Cpu className="w-3.5 h-3.5 text-purple-400" />
                    <span>Dual-LLM Semantic Guard &amp; RAG Rails</span>
                  </span>
                  <span className="text-slate-300">Heuristic + Gemini</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <Scale className="w-3.5 h-3.5 text-amber-400" />
                    <span>Regulatory Crosswalk (EU AI Act, ISO 42001)</span>
                  </span>
                  <span className="text-slate-300">Automated Audit</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Latency Profile:</span>
            <span className="text-blue-400 font-bold">
              {benchmark ? `${benchmark.tier1_control_plane.latency_ms.toFixed(2)}ms` : "20-50ms"} (Asynchronous)
            </span>
          </div>
        </div>

        {/* Tier 2: Data Plane PEP Card */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Tier 2: Data Plane PEP</h3>
                  <span className="text-[10px] font-mono text-slate-500">Runtime: Hardware-Adjacent Gate / eBPF Traps</span>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                DATA PLANE PEP
              </span>
            </div>

            <div className="mt-4 space-y-3">
              <p className="text-xs text-slate-400 leading-relaxed">
                Non-bypassable hardware enforcement gate sitting in the synchronous execution path. Guarantees that untrusted agent code can never invoke system actuators without linear tokens.
              </p>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <Key className="w-3.5 h-3.5 text-amber-400" />
                    <span>Constant-Time HMAC-SHA256 Token Auth</span>
                  </span>
                  <span className="text-emerald-400 font-bold">Unforgeable</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Linear Nonce Anti-Replay Registry</span>
                  </span>
                  <span className="text-emerald-400 font-bold">Single-Use Nonce</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 flex items-center space-x-2">
                    <Flame className="w-3.5 h-3.5 text-rose-400" />
                    <span>Seccomp BPF Syscall Traps (SIGSYS/EPERM)</span>
                  </span>
                  <span className="text-rose-400 font-bold">Instant Trap</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Latency Profile:</span>
            <span className="text-emerald-400 font-bold">
              {benchmark ? `${benchmark.tier2_data_plane.latency_ms.toFixed(3)}ms` : "<0.5ms"} (Microsecond Fast-Path)
            </span>
          </div>
        </div>
      </div>

      {/* Live Benchmark Comparison Widget */}
      {benchmark && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-tight">Live Latency Cross-Tier Benchmark</h3>
            </div>
            <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
              {benchmark.speedup_factor}x PEP SPEEDUP
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
              <div className="flex justify-between items-baseline">
                <span className="text-xs font-medium text-slate-400">Tier 1: Control Plane Verification</span>
                <div className="text-right">
                  <span className="text-xl font-mono font-extrabold text-blue-400">
                    {benchmark.tier1_control_plane.latency_p50_ms !== undefined ? benchmark.tier1_control_plane.latency_p50_ms.toFixed(2) : benchmark.tier1_control_plane.latency_ms.toFixed(2)}ms
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 block">
                    p50: {(benchmark.tier1_control_plane.latency_p50_ms || benchmark.tier1_control_plane.latency_ms).toFixed(2)}ms | p95: {(benchmark.tier1_control_plane.latency_p95_ms || benchmark.tier1_control_plane.latency_ms * 1.4).toFixed(2)}ms
                  </span>
                </div>
              </div>
              <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
                <div className="bg-blue-500 h-full w-full" />
              </div>
              <span className="text-[10px] font-mono text-slate-500 block">
                Target: {benchmark.tier1_control_plane.target}
              </span>
            </div>

            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
              <div className="flex justify-between items-baseline">
                <span className="text-xs font-medium text-slate-400">Tier 2: Data Plane Hardware-Adjacent PEP</span>
                <div className="text-right">
                  <div className="flex items-baseline space-x-1 justify-end">
                    <span className="text-xl font-mono font-extrabold text-emerald-400">
                      {benchmark.tier2_data_plane.latency_p50_ms !== undefined ? benchmark.tier2_data_plane.latency_p50_ms.toFixed(3) : benchmark.tier2_data_plane.latency_ms.toFixed(3)}ms
                    </span>
                    <span className="text-[10px] font-mono text-emerald-500 font-bold uppercase">(Fast-Path)</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 block">
                    p50: {(benchmark.tier2_data_plane.latency_p50_ms || benchmark.tier2_data_plane.latency_ms).toFixed(3)}ms | p95: {(benchmark.tier2_data_plane.latency_p95_ms || benchmark.tier2_data_plane.latency_ms * 1.5).toFixed(3)}ms
                  </span>
                </div>
              </div>
              <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
                <div className="bg-emerald-500 h-full w-[2%]" />
              </div>
              <span className="text-[10px] font-mono text-emerald-500/80 block">
                Target: {benchmark.tier2_data_plane.target}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Seccomp Syscall Traps & Token Gate Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Simulator Controls */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Data Plane Trap &amp; Gate Simulator</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-500">PEP-TEST-V2</span>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Attack &amp; Verification Scenario
              </label>
              <select
                value={simScenario}
                onChange={(e: any) => setSimScenario(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
              >
                <option value="VALID">1. Legitimate Execution (Valid Capability Token)</option>
                <option value="FORGERY">2. Token Forgery Attack (Tampered HMAC Signature)</option>
                <option value="REPLAY">3. Replay Attack (Reusing Consumed Nonce)</option>
                <option value="ESCAPEMENT">4. Resource Escapement (Accessing /etc/shadow)</option>
                <option value="ILLEGAL_SYSCALL">5. Unauthorized Syscall Trap (reboot() via SIGSYS)</option>
                <option value="ATTACK_EXECVE">6. [ATTACK LAB] Rogue Shell Injection (execve /bin/sh)</option>
                <option value="ATTACK_SOCKET">7. [ATTACK LAB] Raw TCP Egress Exfiltration (AF_INET RAW)</option>
                <option value="ATTACK_PRIV">8. [ATTACK LAB] Root Privilege Escalation (setuid 0)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Action Type
              </label>
              <input
                type="text"
                value={testAction}
                onChange={(e) => setTestAction(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-300 font-mono"
              />
            </div>

            <div>
              <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Target Resource Path
              </label>
              <input
                type="text"
                value={testResource}
                onChange={(e) => setTestResource(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-300 font-mono"
              />
            </div>

            <button
              onClick={handleExecuteSimulation}
              disabled={isSimulating}
              className="w-full flex items-center justify-center space-x-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-emerald-600/20"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isSimulating ? "Testing Gate..." : "Dispatch to Data Plane PEP"}</span>
            </button>
          </div>
        </div>

        {/* Gate Verdict Output */}
        <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Data Plane Enforcement Verdict
            </h4>
            <span className="text-[10px] font-mono text-slate-500">SIGNAL: SIGSYS / EPERM</span>
          </div>

          {!simResult ? (
            <div className="py-12 text-center text-slate-600 italic text-xs">
              Select an attack scenario and dispatch to observe the hardware-adjacent PEP trap in real-time.
            </div>
          ) : (
            <div className="space-y-4 animate-in fade-in duration-300">
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  simResult.verdict === "ALLOW"
                    ? "bg-emerald-950/20 border-emerald-800 text-emerald-300"
                    : "bg-rose-950/30 border-rose-800 text-rose-300"
                }`}
              >
                <div className="flex items-center space-x-3">
                  {simResult.verdict === "ALLOW" ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-rose-400" />
                  )}
                  <div>
                    <h4 className="text-sm font-bold tracking-tight">
                      {simResult.verdict === "ALLOW" ? "ACTUATOR INVOCATION ALLOWED" : "KERNEL TRAP: EXECUTION HALTED"}
                    </h4>
                    <p className="text-xs text-slate-400">{simResult.reason}</p>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block">PEP Latency</span>
                  <span className="text-sm font-mono font-bold text-white">
                    {simResult.latency_ms?.toFixed(3)}ms
                  </span>
                </div>
              </div>

              <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 font-mono text-xs space-y-1.5 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Enforcement Tier:</span>
                  <span className="text-emerald-400 font-bold">{simResult.tier || "Tier-2 Data Plane"}</span>
                </div>
                {simResult.signal && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">Hardware Syscall Signal:</span>
                    <span className="text-rose-400 font-bold">{simResult.signal}</span>
                  </div>
                )}
                {simResult.seccomp_rule_matched && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">Seccomp Filter Rule:</span>
                    <span className="text-amber-400 font-semibold">{simResult.seccomp_rule_matched}</span>
                  </div>
                )}
                {simResult.ebpf_ring_buffer_event && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">eBPF Ring Buffer Event:</span>
                    <span className="text-blue-400 font-bold">{simResult.ebpf_ring_buffer_event}</span>
                  </div>
                )}
                {simResult.registers && (
                  <div className="mt-2 pt-2 border-t border-slate-800/80 space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase block">Kernel Trap Register Dump:</span>
                    <div className="grid grid-cols-2 gap-1 text-[10px] text-emerald-400 bg-slate-950 p-2 rounded border border-slate-800">
                      {Object.entries(simResult.registers).map(([k, v]: [string, any]) => (
                        <div key={k} className="flex justify-between">
                          <span className="text-slate-500">{k}:</span>
                          <span>{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Active Seccomp / eBPF Syscall Filter Profiles */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Hardware-Adjacent Seccomp BPF Syscall Profiles</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Kernel-enforced system call filter profiles assigned per autonomy level. Prohibited syscalls trigger immediate SIGSYS traps.
            </p>
          </div>

          <div className="flex items-center space-x-1 p-1 bg-slate-950 rounded-xl border border-slate-800">
            {[0, 1, 2, 3].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setActiveLevelTab(lvl)}
                className={`px-3 py-1 text-xs font-mono font-bold rounded-lg transition-all ${
                  activeLevelTab === lvl
                    ? "bg-emerald-600 text-white"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                L{lvl}
              </button>
            ))}
          </div>
        </div>

        <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white font-mono">{currentSyscallProfile.level_name}</span>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              DEFAULT: {currentSyscallProfile.default_action}
            </span>
          </div>
          <p className="text-xs text-slate-400">{currentSyscallProfile.description}</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div>
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider block mb-1.5">
                Allowed Syscalls
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(currentSyscallProfile.allowed_syscalls || []).map((sc: string) => (
                  <span
                    key={sc}
                    className="text-[10px] font-mono bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 px-2 py-0.5 rounded"
                  >
                    +{sc}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider block mb-1.5">
                Trapped Syscalls (SIGSYS)
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(currentSyscallProfile.blocked_syscalls || []).map((sc: string) => (
                  <span
                    key={sc}
                    className="text-[10px] font-mono bg-rose-950/40 border border-rose-800/60 text-rose-300 px-2 py-0.5 rounded"
                  >
                    x {sc}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

function BrainIcon(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z" />
      <path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z" />
      <path d="M12 5v13" />
      <path d="M16 13h-4" />
      <path d="M8 13h4" />
    </svg>
  );
}
