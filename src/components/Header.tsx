import React from "react";
import { 
  Shield, 
  Terminal, 
  Activity, 
  Settings, 
  Cpu, 
  ChevronRight,
  ShieldCheck,
  Lock,
  Layers,
  Database,
  LogIn,
  LogOut,
  User as UserIcon,
  CheckCircle2,
  AlertCircle,
  Zap,
  AlertOctagon,
  Users
} from "lucide-react";
import { User } from "firebase/auth";

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  trustScore: number;
  autonomyLevel: number;
  dbConnected?: boolean;
  currentUser?: User | null;
  onSignIn?: () => void;
  onSignOut?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ 
  activeTab, 
  setActiveTab,
  trustScore,
  autonomyLevel,
  dbConnected = false,
  currentUser = null,
  onSignIn,
  onSignOut
}) => {
  const tabs = [
    { id: "studio", label: "Intent Studio", icon: Terminal },
    { id: "dualtier", label: "Dual-Tier Arch", icon: Zap },
    { id: "incidents", label: "Agent ACLs & Kill-Switch", icon: AlertOctagon },
    { id: "pep", label: "PEP Fleet", icon: Layers },
    { id: "authzen", label: "AuthZEN / SPIFFE", icon: Lock },
    { id: "autopilot", label: "Autopilot", icon: Cpu },
    { id: "consent", label: "Consent Matrix", icon: ShieldCheck },
    { id: "audit", label: "Causal Audit", icon: Activity },
    { id: "compliance", label: "Governance", icon: CheckCircle2 },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/80 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-[1440px] mx-auto px-6 h-16 flex items-center justify-between gap-4">
        {/* Zone 1: Brand wordmark */}
        <div className="flex items-center space-x-3 shrink-0 cursor-pointer" onClick={() => setActiveTab("studio")}>
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20">
            <Shield className="w-5 h-5 text-emerald-400" />
          </div>
          <span className="text-lg font-bold tracking-tight text-white whitespace-nowrap">
            Guardrail OS
          </span>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="flex items-center gap-2 sm:gap-4 overflow-x-auto py-2 text-xs sm:text-sm font-medium scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg transition-all whitespace-nowrap shrink-0 text-xs ${
                  isActive 
                    ? "text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 font-bold" 
                    : "text-slate-400 hover:text-white hover:bg-slate-900 border border-transparent"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="hidden xl:flex items-center text-[10px] font-mono text-slate-400 space-x-2 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <Database className="w-3 h-3 text-emerald-400" />
            <span className="text-slate-500 uppercase">DB:</span>
            <span className="text-emerald-400 font-bold truncate max-w-[130px]" title="ai-studio-guardrail-88e17807-6d73-4f90-8eb4-0a23caabe4b4">
              GUARDRAIL-DB
            </span>
            <span className={`w-1.5 h-1.5 rounded-full ${dbConnected ? "bg-emerald-400" : "bg-emerald-500 animate-pulse"}`}></span>
          </div>

          <div className="hidden lg:flex items-center text-[10px] font-mono text-slate-500 space-x-2 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>KERNEL: L{autonomyLevel}</span>
          </div>

          {currentUser ? (
            <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1">
              {currentUser.photoURL ? (
                <img 
                  src={currentUser.photoURL} 
                  alt={currentUser.displayName || "User"} 
                  className="w-5 h-5 rounded-full"
                />
              ) : (
                <UserIcon className="w-4 h-4 text-emerald-400" />
              )}
              <span className="text-xs font-mono text-slate-300 max-w-[100px] truncate">
                {currentUser.displayName || currentUser.email?.split("@")[0]}
              </span>
              <button 
                onClick={onSignOut}
                title="Sign Out"
                className="text-slate-500 hover:text-rose-400 transition-colors p-0.5 ml-1"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button 
              onClick={onSignIn}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-900 border border-slate-700 hover:bg-slate-800 hover:text-white rounded-lg transition-all"
            >
              <LogIn className="w-3.5 h-3.5 text-emerald-400" />
              <span>Sign In</span>
            </button>
          )}
        </div>
      </div>
      
      {/* Sub-header Breadcrumbs / Status Strip */}
      <div className="bg-slate-900/40 border-b border-slate-800/50 py-2">
        <div className="max-w-[1440px] mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center space-x-2 text-[11px] font-medium text-slate-500 uppercase tracking-wider">
            <span>Root</span>
            <ChevronRight className="w-3 h-3" />
            <span className="text-slate-300">
              {tabs.find(t => t.id === activeTab)?.label}
            </span>
          </div>
          
          <div className="flex items-center space-x-6 text-[10px] font-mono tabular-nums">
            <div className="flex items-center space-x-2">
              <span className="text-slate-500 uppercase">Enforcement Latency:</span>
              <span className="text-emerald-400">4.2ms</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-slate-500 uppercase">Trust Index:</span>
              <span className={trustScore >= 70 ? "text-emerald-400" : "text-rose-400"}>
                {trustScore.toFixed(1)}%
              </span>
            </div>
            <div className="hidden sm:flex items-center space-x-2">
              <span className="text-slate-500 uppercase">Persistence:</span>
              <span className="text-blue-400 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3 text-blue-400" />
                <span>STATEFUL</span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
