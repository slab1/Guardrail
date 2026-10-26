// Guardrail Plan Compiler: Intent -> Static, Analyzable Action Plan

import {
  AutonomyLevel,
  CATEGORY_REQUIRED_LEVEL,
  PlanStep,
  TOOL_CATEGORY_MAP,
  ToolCategory,
  ValidatedPlan,
} from "../types/guardrail";
import { defaultTokenService } from "./tokenService";

export interface IntentAction {
  verb: string;
  target: string;
  context?: string;
}

export function parseIntentToActions(intent: string): IntentAction[] {
  const normalized = intent.trim().replace(/\s+/g, " ");
  const actions: IntentAction[] = [];

  // Patterns for multi-step intents
  const clauses = normalized.split(/\b(?:and then|then|after that|followed by|and)\b/i);

  const verbMap: Record<string, string> = {
    read: "read",
    inspect: "read",
    view: "read",
    fetch: "read",
    get: "read",
    list: "read",
    check: "read",
    validate: "read",
    query: "read",
    search: "read",
    write: "write",
    create: "write",
    save: "write",
    update: "write",
    modify: "write",
    delete: "write",
    remove: "write",
    upload: "write",
    post: "write",
    execute: "execute",
    run: "execute",
    deploy: "execute",
    shell: "execute",
    compile: "execute",
    build: "execute",
    admin: "admin",
    grant: "admin",
    rotate: "admin",
    reboot: "admin",
  };

  clauses.forEach((clause) => {
    const trimmed = clause.trim();
    if (!trimmed) return;

    // Search for verb
    let matchedVerb = "";
    let matchedTarget = trimmed;

    const words = trimmed.split(" ");
    for (let i = 0; i < words.length; i++) {
      const lower = words[i].toLowerCase();
      if (verbMap[lower]) {
        matchedVerb = lower;
        matchedTarget = words.slice(i + 1).join(" ");
        break;
      }
    }

    if (!matchedVerb) {
      if (trimmed.toLowerCase().includes("file") || trimmed.toLowerCase().includes("config")) {
        matchedVerb = "read";
      } else if (trimmed.toLowerCase().includes("api") || trimmed.toLowerCase().includes("http")) {
        matchedVerb = "get";
      } else {
        matchedVerb = "read";
      }
    }

    actions.push({
      verb: matchedVerb,
      target: matchedTarget || "system_resource",
    });
  });

  if (actions.length === 0) {
    actions.push({
      verb: "read",
      target: intent,
    });
  }

  return actions;
}

export function mapActionToStep(
  action: IntentAction,
  index: number,
  planId: string
): PlanStep {
  const v = action.verb.toLowerCase();
  const target = action.target.trim();

  let actionType = "file_read";
  let category: ToolCategory = "read";
  const resource = target;
  let reversible = true;
  let riskLevel: "low" | "medium" | "high" = "low";

  if (v === "delete" || v === "remove") {
    actionType = "file_delete";
    category = "write";
    reversible = false; // Destructive!
    riskLevel = "high";
  } else if (v === "write" || v === "create" || v === "update" || v === "modify") {
    actionType = target.includes("http") || target.includes("api") ? "http_post" : "file_write";
    category = "write";
    reversible = true; // Rollbackable via LSFS
    riskLevel = "medium";
  } else if (v === "execute" || v === "run" || v === "shell" || v === "deploy" || v === "build") {
    actionType = "shell_command";
    category = "execute";
    reversible = false;
    riskLevel = "high";
  } else if (v === "admin" || v === "rotate" || v === "grant" || v === "reboot") {
    actionType = "admin_tool";
    category = "admin";
    reversible = false;
    riskLevel = "high";
  } else if (target.startsWith("http://") || target.startsWith("https://") || target.includes("/api/")) {
    actionType = "http_get";
    category = "read";
    riskLevel = "low";
  } else {
    actionType = "file_read";
    category = "read";
    riskLevel = "low";
  }

  // Pre-condition & post-condition analysis
  const preConditions: string[] = [];
  const postConditions: string[] = [];

  if (actionType === "file_write") {
    preConditions.push("lsfs_snapshot_created");
    postConditions.push("checksum_verified");
  } else if (actionType === "file_read") {
    preConditions.push("path_within_sandbox");
  } else if (actionType === "shell_command") {
    preConditions.push("firecracker_microvm_ready", "seccomp_profile_applied");
    postConditions.push("process_exit_code_0");
  } else if (actionType === "admin_tool") {
    preConditions.push("elevated_sponsor_consent", "mfa_biometric_valid");
  }

  const requiredLevel = CATEGORY_REQUIRED_LEVEL[category];

  return {
    id: `step_${index + 1}`,
    description: `${action.verb.toUpperCase()} on ${target}`,
    action_type: actionType,
    resource,
    category,
    required_level: requiredLevel,
    reversible,
    pre_conditions: preConditions,
    post_conditions: postConditions,
    risk_level: riskLevel,
  };
}

export async function compileAndValidatePlan(
  intent: string,
  agentClass: string = "coding",
  userId: string = "developer_01",
  currentAutonomy: AutonomyLevel = AutonomyLevel.L1,
  customPlanId?: string
): Promise<ValidatedPlan> {
  const planId = customPlanId || `plan_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
  const actions = parseIntentToActions(intent);
  const steps: PlanStep[] = actions.map((act, idx) => mapActionToStep(act, idx, planId));

  const validationErrors: string[] = [];

  // Static checks
  // 1. Check for unauthorized steps given autonomy level
  steps.forEach((step) => {
    if (step.required_level > currentAutonomy) {
      validationErrors.push(
        `Step ${step.id} (${step.action_type}) requires Autonomy Level L${step.required_level}, but current agent level is L${currentAutonomy}`
      );
    }

    // Dangerous path check
    if (step.resource) {
      const lower = step.resource.toLowerCase();
      if (lower.includes("/etc/shadow") || lower.includes("/etc/passwd") || lower.includes("/root/.ssh")) {
        validationErrors.push(`Step ${step.id} attempts access to restricted host security path: ${step.resource}`);
      }
    }
  });

  // Calculate overall risk
  let riskScore: "low" | "medium" | "high" = "low";
  if (steps.some((s) => s.risk_level === "high")) {
    riskScore = "high";
  } else if (steps.some((s) => s.risk_level === "medium")) {
    riskScore = "medium";
  }

  // Generate tokens for each step
  const stepTokens: Record<string, string> = {};
  for (const step of steps) {
    const { token } = await defaultTokenService.createStepToken(
      planId,
      step.id,
      intent,
      agentClass,
      userId,
      currentAutonomy
    );
    stepTokens[step.id] = token;
  }

  // Generate plan-level token
  const { token: planToken } = await defaultTokenService.createPlanToken(
    planId,
    intent,
    agentClass,
    userId,
    currentAutonomy
  );

  return {
    id: planId,
    intent,
    description: `Generated Plan with ${steps.length} atomic steps for intent: "${intent.slice(0, 60)}..."`,
    agent_class: agentClass,
    user_id: userId,
    autonomy_level: currentAutonomy,
    steps,
    model_required: "nvidia/nemotron-3-nano-30b-a3b-reasoning",
    created_at: new Date().toISOString(),
    validation_errors: validationErrors,
    is_valid: validationErrors.length === 0,
    step_tokens: stepTokens,
    plan_token: planToken,
    risk_score: riskScore,
  };
}
