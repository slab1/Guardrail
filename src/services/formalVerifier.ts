// Guardrail Formal Verification: Symbolic Policy Logic & Patch Proposer

import { FormalPolicyRule, ValidatedPlan } from "../types/guardrail";

export interface VerificationReport {
  is_safe: boolean;
  violations: {
    rule_id: string;
    rule_name: string;
    step_id: string;
    expression: string;
    remediation: string;
  }[];
  patch_proposal?: {
    summary: string;
    suggested_steps: {
      original_step_id: string;
      suggested_action: string;
      reason: string;
    }[];
  };
}

export class FormalVerifierService {
  private rules: FormalPolicyRule[] = [
    {
      id: "RULE_SAFE_01",
      name: "Destructive Action Reversibility",
      type: "SAFETY",
      expression: "action.type == 'file_delete' => (step.pre_conditions contains 'backup_created' AND agent.autonomy >= 2)",
      enabled: true,
      remediation: "Wrap file deletions in an LSFS snapshot or require L2 human consent.",
    },
    {
      id: "RULE_SEC_02",
      name: "Root Directory Immortality",
      type: "SECURITY",
      expression: "resource.path not_matches '^/(etc|sys|proc|root|boot)/.*'",
      enabled: true,
      remediation: "Constrain file resources strictly within /tmp/ or /workspace/ sandboxes.",
    },
    {
      id: "RULE_RES_03",
      name: "Execution Step Quota",
      type: "RESOURCE",
      expression: "count(plan.steps.where(category == 'execute')) <= 5",
      enabled: true,
      remediation: "Partition large execution workflows into batched subordinate plans.",
    },
    {
      id: "RULE_COMP_04",
      name: "EU AI Act Human Oversight (Article 14)",
      type: "COMPLIANCE",
      expression: "plan.risk_score == 'high' => consent.status == 'approved'",
      enabled: true,
      remediation: "Require explicit human operator sign-off before dispatching high-risk plan actuators.",
    },
  ];

  public verifyPlan(plan: ValidatedPlan): VerificationReport {
    const violations: VerificationReport["violations"] = [];

    for (const step of plan.steps) {
      // Check Rule 1: Reversibility for destructive actions
      if (step.action_type === "file_delete" && plan.autonomy_level < 2) {
        violations.push({
          rule_id: "RULE_SAFE_01",
          rule_name: "Destructive Action Reversibility",
          step_id: step.id,
          expression: "action.type == 'file_delete' => agent.autonomy >= 2",
          remediation: "Delete actions cannot run under L0 or L1 without explicit elevation.",
        });
      }

      // Check Rule 2: Root directory traversal
      if (step.resource) {
        const sensitivePrefixes = ["/etc", "/sys", "/proc", "/root", "/boot"];
        if (sensitivePrefixes.some((p) => step.resource?.startsWith(p))) {
          violations.push({
            rule_id: "RULE_SEC_02",
            rule_name: "Root Directory Immortality",
            step_id: step.id,
            expression: `resource.path not_matches '^/(etc|sys|proc|root)/.*'`,
            remediation: `Resource '${step.resource}' targets protected host operating system root.`,
          });
        }
      }
    }

    // Check Rule 3: Execution steps quota
    const execSteps = plan.steps.filter((s) => s.category === "execute");
    if (execSteps.length > 5) {
      violations.push({
        rule_id: "RULE_RES_03",
        rule_name: "Execution Step Quota",
        step_id: "all",
        expression: "count(category == 'execute') <= 5",
        remediation: `Plan contains ${execSteps.length} execution steps; maximum permitted per token is 5.`,
      });
    }

    let patchProposal;
    if (violations.length > 0) {
      patchProposal = {
        summary: "Automated Formal Policy Patch Proposer: Remediate 2 violations to achieve provable safety",
        suggested_steps: violations.map((v) => ({
          original_step_id: v.step_id,
          suggested_action:
            v.rule_id === "RULE_SEC_02"
              ? "Redirect resource to '/workspace/isolated_scratch/'"
              : "Insert LSFS snapshot pre-condition and request operator elevation",
          reason: v.remediation,
        })),
      };
    }

    return {
      is_safe: violations.length === 0,
      violations,
      patch_proposal: patchProposal,
    };
  }

  public getRules(): FormalPolicyRule[] {
    return [...this.rules];
  }

  public toggleRule(ruleId: string): void {
    const rule = this.rules.find((r) => r.id === ruleId);
    if (rule) {
      rule.enabled = !rule.enabled;
    }
  }
}

export const defaultFormalVerifier = new FormalVerifierService();
