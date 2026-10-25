// Guardrail Compliance Service: AI Act, NIST AI RMF, ISO 42001, SOC2

import { ComplianceControl } from "../types/guardrail";

export class ComplianceService {
  private controls: ComplianceControl[] = [
    {
      control_id: "EU-AI-ACT-ART14",
      framework: "EU_AI_ACT",
      title: "Human Oversight (Article 14)",
      description: "High-risk AI systems must be designed to enable natural persons to oversee their operation, intervene, and interrupt.",
      status: "IMPLEMENTED",
      guardrail_module: "Consent Manager & Autonomy Ladder (L0-L3)",
      evidence: "Plan diff review, interactive Explain Deny, and one-click operator interrupt capabilities active.",
    },
    {
      control_id: "EU-AI-ACT-ART15",
      framework: "EU_AI_ACT",
      title: "Accuracy, Robustness and Cybersecurity (Article 15)",
      description: "AI systems must be resilient against attempts to alter their use, outputs, or performance by unauthorized third parties.",
      status: "IMPLEMENTED",
      guardrail_module: "PEP Fleet (Firecracker MicroVMs & LSFS Rollback)",
      evidence: "Actuators isolated in hardware microVMs; files protected by instant cryptographic snapshot rollback.",
    },
    {
      control_id: "NIST-AI-RMF-GOV1.2",
      framework: "NIST_AI_RMF",
      title: "Governance: Accountability & Trust Assessment",
      description: "Policies, procedures, and responsibilities for AI systems are monitored with transparent scoring.",
      status: "IMPLEMENTED",
      guardrail_module: "Autopilot Closed-Loop Trust Scoring",
      evidence: "Real-time algorithmic trust engine (0-100) automatically promotes or demotes autonomy based on incident history.",
    },
    {
      control_id: "NIST-AI-RMF-MEAS2.4",
      framework: "NIST_AI_RMF",
      title: "Measurement: Causal Traceability & Logging",
      description: "System mechanisms capture detailed trace data linking host actions to model decisions and safety policies.",
      status: "IMPLEMENTED",
      guardrail_module: "Causal Audit with eBPF Trace Labels",
      evidence: "SHA-256 hash-chained immutable audit log with cryptographic causal labels linking kernel events to user intent.",
    },
    {
      control_id: "ISO-42001-A.8.2",
      framework: "ISO_42001",
      title: "AI System Operational Controls & Capability Scoping",
      description: "Controls are applied to manage autonomous actuators through bounded permissions.",
      status: "IMPLEMENTED",
      guardrail_module: "Token Service (Intent-Bound Per-Step Tokens)",
      evidence: "Ed25519-signed ephemeral capability tokens (TTL <= 15m) strictly bind step IDs and prevent cross-plan replay.",
    },
    {
      control_id: "SOC2-CC6.6",
      framework: "SOC2",
      title: "Logical Boundary Protection & Egress Filtering",
      description: "The entity implements logical boundaries to restrict unauthorized outbound transmission of sensitive data.",
      status: "IMPLEMENTED",
      guardrail_module: "PEP-Net Egress Gateway & AuthZEN PDP",
      evidence: "Default-deny network proxy with domain allowlisting and automated bearer secret masking.",
    },
  ];

  public getControls(framework?: string): ComplianceControl[] {
    if (framework && framework !== "ALL") {
      return this.controls.filter((c) => c.framework === framework);
    }
    return [...this.controls];
  }

  public getScore(framework?: string): {
    score: number;
    implemented: number;
    total: number;
  } {
    const list = this.getControls(framework);
    const implemented = list.filter((c) => c.status === "IMPLEMENTED").length;
    return {
      score: list.length > 0 ? Math.round((implemented / list.length) * 100) : 100,
      implemented,
      total: list.length,
    };
  }
}

export const defaultCompliance = new ComplianceService();
