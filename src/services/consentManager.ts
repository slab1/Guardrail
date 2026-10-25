// Guardrail Consent Manager - Plan-level consent, autonomy ladder escalation & Explain Deny

import {
  ConsentDecision,
  ConsentRequest,
  ConsentStatus,
  ValidatedPlan,
} from "../types/guardrail";

export class ConsentManager {
  private requests: Map<string, ConsentRequest> = new Map();
  private decisions: Map<string, ConsentDecision> = new Map();
  public autoApproveLowRisk: boolean = true;
  public defaultTtlSeconds: number = 3600; // 1 hour

  public createRequest(plan: ValidatedPlan): ConsentRequest {
    const now = Date.now();
    const req: ConsentRequest = {
      plan_id: plan.id,
      plan_description: plan.description,
      steps_summary: plan.steps.map((s) => ({
        step_id: s.id,
        description: s.description,
        action_type: s.action_type,
        resource: s.resource,
        risk_level: s.risk_level,
        category: s.category,
      })),
      risk_level: plan.risk_score,
      requested_at: now,
      expires_at: now + this.defaultTtlSeconds * 1000,
      status: ConsentStatus.PENDING,
      user_id: plan.user_id,
    };

    // Auto approve if low risk and enabled
    if (this.autoApproveLowRisk && plan.risk_score === "low" && plan.is_valid) {
      req.status = ConsentStatus.APPROVED;
      const stepApprovals: Record<string, boolean> = {};
      plan.steps.forEach((s) => (stepApprovals[s.id] = true));
      this.decisions.set(plan.id, {
        plan_id: plan.id,
        approved: true,
        step_approvals: stepApprovals,
        conditions: ["auto_approved_low_risk_policy"],
        decided_at: now,
        decided_by: "system_policy_autopilot",
        explanation: "Low risk plan with read-only/idempotent steps automatically approved.",
      });
    }

    this.requests.set(plan.id, req);
    return req;
  }

  public recordDecision(
    planId: string,
    approved: boolean,
    stepApprovals?: Record<string, boolean>,
    decidedBy: string = "human_supervisor",
    explanation?: string
  ): ConsentDecision {
    const req = this.requests.get(planId);
    if (req) {
      req.status = approved ? ConsentStatus.APPROVED : ConsentStatus.DENIED;
    }

    const decision: ConsentDecision = {
      plan_id: planId,
      approved,
      step_approvals: stepApprovals || {},
      conditions: approved ? ["user_verified_blast_radius"] : ["user_denied_risk_profile"],
      decided_at: Date.now(),
      decided_by: decidedBy,
      explanation:
        explanation ||
        (approved
          ? "Explicit human approval granted for elevated autonomy capabilities."
          : "User declined to grant elevated actuator capabilities."),
    };

    this.decisions.set(planId, decision);
    return decision;
  }

  public getRequest(planId: string): ConsentRequest | undefined {
    return this.requests.get(planId);
  }

  public getDecision(planId: string): ConsentDecision | undefined {
    return this.decisions.get(planId);
  }

  public isStepApproved(planId: string, stepId: string): boolean {
    const decision = this.decisions.get(planId);
    if (!decision) return false;
    if (!decision.approved) return false;
    // If granular steps are defined, check the specific step
    if (stepId in decision.step_approvals) {
      return decision.step_approvals[stepId];
    }
    return decision.approved;
  }

  public explainDenial(plan: ValidatedPlan, stepId?: string): {
    title: string;
    reason: string;
    violatedRule: string;
    remediation: string;
  } {
    if (stepId) {
      const step = plan.steps.find((s) => s.id === stepId);
      if (step) {
        return {
          title: `Step ${step.id} Denied`,
          reason: `Action '${step.action_type}' targeting '${step.resource || "system"}' exceeds agent autonomy L${plan.autonomy_level}.`,
          violatedRule: `Guardrail PEP-MCP Rule: Category '${step.category}' requires Autonomy Level L${step.required_level}`,
          remediation: `Elevate agent autonomy to L${step.required_level} or request explicit one-time human step approval.`,
        };
      }
    }

    if (plan.validation_errors.length > 0) {
      return {
        title: "Plan Static Validation Failure",
        reason: plan.validation_errors.join("; "),
        violatedRule: "Guardrail Plan Compiler Pre-Flight Safety Verification",
        remediation: "Revise natural language prompt to avoid privileged actuators or destructive actions.",
      };
    }

    return {
      title: "Consent Denied by Human Operator",
      reason: "The operator evaluated the plan diff and declined the requested capabilities.",
      violatedRule: "Guardrail Human-In-The-Loop (HITL) Consent Ladder",
      remediation: "Resubmit intent with reduced tool scope or partitioned execution.",
    };
  }
}

export const defaultConsentManager = new ConsentManager();
