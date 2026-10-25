import React, { useState, useEffect } from "react";
import { defaultTokenService } from "../services/tokenService";
import { TokenPayload } from "../types/guardrail";
import { Key, ShieldCheck, XCircle, X, Copy, Check, Clock } from "lucide-react";

interface TokenInspectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  tokenString: string;
  stepId?: string;
}

export const TokenInspectorModal: React.FC<TokenInspectorModalProps> = ({
  isOpen,
  onClose,
  tokenString,
  stepId,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);

  useEffect(() => {
    if (tokenString && isOpen) {
      const payload = defaultTokenService.decodeToken(tokenString);
      if (payload) {
        defaultTokenService
          .validateToken(tokenString, payload.plan_id, payload.step_id)
          .then((res) => setVerificationResult(res));
      } else {
        setVerificationResult({ valid: false, reason: "Unable to decode JWT format" });
      }
    }
  }, [tokenString, isOpen]);

  if (!isOpen) return null;

  const payload: TokenPayload | null = defaultTokenService.decodeToken(tokenString);

  const handleCopy = () => {
    navigator.clipboard.writeText(tokenString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-amber-500/10 border border-amber-500/20 rounded-xl">
              <Key className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">
                Cryptographic Capability Token Inspector
              </h3>
              <p className="text-xs text-slate-400">
                {stepId ? `Bound to Step: ${stepId}` : "Plan-Level Root Token"}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Verification Status Banner */}
        {verificationResult && (
          <div
            className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between ${
              verificationResult.valid
                ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
                : "bg-rose-950/40 border-rose-800 text-rose-300"
            }`}
          >
            <div className="flex items-center space-x-2">
              {verificationResult.valid ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-400" />
              )}
              <span>
                {verificationResult.valid
                  ? "SIGNATURE VALID · CAPABILITY ACTIVE"
                  : `INVALID: ${verificationResult.reason}`}
              </span>
            </div>
            <span className="text-[10px] opacity-80">Ed25519-HMAC</span>
          </div>
        )}

        {/* Decoded Claims */}
        {payload ? (
          <div className="space-y-3">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
              Decoded Claims &amp; Intent Binding
            </span>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Token Type</span>
                <span className="text-amber-400 uppercase font-bold">{payload.token_type}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Autonomy Level</span>
                <span className="text-blue-400 font-bold">L{payload.autonomy_level}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Bound Plan ID</span>
                <span className="text-slate-300 truncate block">{payload.plan_id}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Bound Step ID</span>
                <span className="text-slate-300 truncate block">{payload.step_id || "ALL_STEPS"}</span>
              </div>

              <div className="col-span-2 p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Signed Natural Intent</span>
                <span className="text-slate-200 font-sans">{payload.intent}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Agent Class / User</span>
                <span className="text-slate-300">
                  {payload.agent_class} ({payload.user_id})
                </span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Replay Nonce</span>
                <span className="text-slate-400 truncate block">{payload.nonce}</span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Issued At</span>
                <span className="text-slate-400">
                  {new Date(payload.issued_at * 1000).toLocaleTimeString()}
                </span>
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Expires At</span>
                <span className="text-slate-400">
                  {new Date(payload.expires_at * 1000).toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-4 text-xs text-rose-400 bg-rose-950/20 rounded">
            Invalid token format.
          </div>
        )}

        {/* Raw Token String */}
        <div className="space-y-1.5 pt-2 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">
              Raw Ephemeral Capability (gr_*)
            </span>
            <button
              onClick={handleCopy}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center space-x-1"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied" : "Copy Token"}</span>
            </button>
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[10px] font-mono text-slate-400 break-all max-h-24 overflow-y-auto">
            {tokenString || "(empty)"}
          </pre>
        </div>
      </div>
    </div>
  );
};
