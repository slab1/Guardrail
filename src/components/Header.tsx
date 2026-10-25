import React from "react";
import {
  Shield,
  Activity,
  Layers,
  Cpu,
  Lock,
  FileCheck,
  Zap,
} from "lucide-react";

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  trustScore: number;
  autonomyLevel: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  trustScore,
  autonomyLevel,
}) => {
  const tabs = [
    { id: "studio", label: "Intent & Plan Studio", icon: Zap },
    { id: "consent", label: "Consent & Ladder", icon: Lock },
    { id: "pep", label: "PEP Fleet & Sandboxes", icon: Layers },
    { id: "audit", label: "Causal Audit (eBPF)", icon: Activity },
    { id: "autopilot", label: "Autopilot Trust", icon: Cpu },
    { id: "authzen", label: "AuthZEN & SPIFFE", icon: Shield },
    { id: "compliance", label: "Formal & Compliance", icon: FileCheck },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Tagline */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20 ring-1 ring-blue-400/30">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight text-white font-mono">
                  GUARDRAIL
                </span>
                <span className="text-[10px] uppercase font-semibold tracking-wider px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                  v2.4 Kernel
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Authorization &amp; Safety Operating Layer for AI Agents
              </p>
            </div>
          </div>

          {/* System Telemetry & Status Badges */}
          <div className="flex items-center space-x-4">
            <div className="hidden md:flex items-center space-x-3 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
              <div className="flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-slate-400">PDP:</span>
                <span className="text-emerald-400 font-mono font-medium">ENFORCING</span>
              </div>
              <div className="h-3 w-px bg-slate-800" />
              <div className="flex items-center space-x-1.5">
                <span className="text-slate-400">Autonomy:</span>
                <span className="text-indigo-400 font-mono font-bold">L{autonomyLevel}</span>
              </div>
              <div className="h-3 w-px bg-slate-800" />
              <div className="flex items-center space-x-1.5">
                <span className="text-slate-400">Trust:</span>
                <span
                  className={`font-mono font-bold ${
                    trustScore >= 70
                      ? "text-emerald-400"
                      : trustScore >= 40
                      ? "text-amber-400"
                      : "text-rose-400"
                  }`}
                >
                  {trustScore.toFixed(1)}/100
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="flex space-x-1 overflow-x-auto pb-1 scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-t-lg text-xs sm:text-sm font-medium transition-all whitespace-nowrap border-b-2 ${
                  isActive
                    ? "border-blue-500 text-blue-400 bg-blue-500/10"
                    : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-slate-400"}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
