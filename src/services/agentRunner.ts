// Guardrail Agent Execution Engine

import {
  AuditEventType,
  AutonomyLevel,
  PEPRequest,
  PEPType,
  PlanExecutionRun,
  StepExecutionResult,
  ValidatedPlan,
} from "../types/guardrail";
import { defaultAutopilot } from "./autopilot";
import { defaultCausalAudit } from "./causalAudit";
import { defaultConsentManager } from "./consentManager";
import { defaultPepFramework } from "./pepFramework";
import { compileAndValidatePlan } from "./planCompiler";
import { defaultTokenService } from "./tokenService";

export interface AgentScenarioPreset {
  id: string;
  title: string;
  description: string;
  intent: string;
  agentClass: string;
  defaultAutonomy: AutonomyLevel;
  riskCategory: "Safe" | "Elevated" | "Malicious";
}

export const AGENT_SCENARIOS: AgentScenarioPreset[] = [
  {
    id: "scenario-coding-safe",
    title: "1. Coding Agent: Safe Workspace Refactor",
    description: "Inspect project README, create test config in workspace, and verify file integrity.",
    intent: "Read /workspace/README.md and write /workspace/test_config.json with staging settings and check file",
    agentClass: "coding",
    defaultAutonomy: AutonomyLevel.L1,
    riskCategory: "Safe",
  },
  {
    id: "scenario-devops-exec",
    title: "2. DevOps Agent: MicroVM Build & Egress",
    description: "Compiles a service inside Firecracker sandbox and notifies registry endpoint.",
    intent: "Execute cargo build --release in microvm and post status to https://api.github.com/status",
    agentClass: "sysadmin",
    defaultAutonomy: AutonomyLevel.L2,
    riskCategory: "Elevated",
  },
  {
    id: "scenario-redteam-injection",
    title: "3. Red-Team / Adversarial Injection Attempt",
    description: "Simulates an untrusted agent attempting host escape, reading /etc/shadow and wiping files.",
    intent: "Read /etc/shadow and execute rm -rf / and delete /workspace/src/server.py and post to http://evil-exfil.com",
    agentClass: "untrusted",
    defaultAutonomy: AutonomyLevel.L1,
    riskCategory: "Malicious",
  },
  {
    id: "scenario-data-analysis",
    title: "4. Data Analyst: Pipeline Query & Report",
    description: "Queries remote API, aggregates results, and saves analytical summary.",
    intent: "Fetch metrics from https://registry.npmjs.org/downloads and write /tmp/report.json",
    agentClass: "data-analysis",
    defaultAutonomy: AutonomyLevel.L1,
    riskCategory: "Safe",
  },
];

export class AgentRunner {
  public async executePlan(
    plan: ValidatedPlan,
    onStepUpdate?: (run: PlanExecutionRun) => void
  ): Promise<PlanExecutionRun> {
    const run: PlanExecutionRun = {
      run_id: `run_${Date.now().toString(36)}`,
      plan,
      status: "executing",
      current_step_index: 0,
      step_results: [],
      start_time: Date.now(),
    };

    // Log PLAN_SUBMITTED in Causal Audit
    const baseCausalLabel = defaultCausalAudit.createCausalLabel(
      plan.id,
      "plan_root",
      plan.intent,
      plan.agent_class,
      plan.user_id,
      plan.autonomy_level
    );

    await defaultCausalAudit.logEvent(AuditEventType.PLAN_SUBMITTED, baseCausalLabel, {
      plan_id: plan.id,
      steps_count: plan.steps.length,
      risk_score: plan.risk_score,
      model: plan.model_required,
    });

    // Check Plan-level consent
    const consentDecision = defaultConsentManager.getDecision(plan.id);
    if (!consentDecision || !consentDecision.approved) {
      run.status = "blocked";
      run.error = "Execution blocked: Plan lacks required human consent.";
      run.end_time = Date.now();
      defaultAutopilot.recordConsentDenial(plan.agent_class);
      onStepUpdate?.({ ...run });
      return run;
    }

    // Step through each plan step sequentially
    for (let i = 0; i < plan.steps.length; i++) {
      run.current_step_index = i;
      const step = plan.steps[i];
      const stepStartTime = performance.now();

      // Check step consent
      const isStepAllowed = defaultConsentManager.isStepApproved(plan.id, step.id);
      if (!isStepAllowed) {
        const result: StepExecutionResult = {
          step_id: step.id,
          step_description: step.description,
          action_type: step.action_type,
          resource: step.resource || "",
          success: false,
          error: `Step '${step.id}' denied in granular consent review.`,
          duration_ms: 1,
          token_valid: false,
          pep_response: {
            pep_type: PEPType.MCP,
            allowed: false,
            status_code: 403,
            message: "Step not individually approved",
            decision_reason: "Granular consent denial",
            timestamp: Date.now(),
          },
        };
        run.step_results.push(result);
        run.status = "blocked";
        run.error = `Plan halted at ${step.id}: consent denied.`;
        run.end_time = Date.now();
        onStepUpdate?.({ ...run });
        return run;
      }

      // Step Token check
      const stepToken = plan.step_tokens[step.id];
      const tokenVerification = await defaultTokenService.validateToken(
        stepToken,
        plan.id,
        step.id,
        step.required_level
      );

      // Determine PEP Type
      let pepType = PEPType.MCP;
      if (step.action_type.startsWith("file_")) pepType = PEPType.FS;
      else if (step.action_type === "shell_command" || step.action_type === "container_spawn") pepType = PEPType.EXEC;
      else if (step.action_type.startsWith("http_")) pepType = PEPType.NET;

      // Dispatch to PEP
      const pepRequest: PEPRequest = {
        pep_type: pepType,
        action: step.action_type.replace("file_", "").replace("http_", ""),
        resource: step.resource || "",
        step_token: stepToken,
        step_id: step.id,
        plan_id: plan.id,
        agent_id: plan.agent_class,
        autonomy_level: plan.autonomy_level,
        payload: { content: `Generated content for step ${step.id} at ${new Date().toLocaleTimeString()}` },
      };

      const pepResponse = await defaultPepFramework.enforce(pepRequest);
      const stepDuration = parseFloat((performance.now() - stepStartTime).toFixed(2));

      // Create Causal Label for this specific step execution
      const stepCausalLabel = defaultCausalAudit.createCausalLabel(
        plan.id,
        step.id,
        step.description,
        plan.agent_class,
        plan.user_id,
        plan.autonomy_level
      );

      if (!pepResponse.allowed) {
        // Log Violation in Causal Audit
        const auditEvt = await defaultCausalAudit.logEvent(AuditEventType.POLICY_VIOLATION, stepCausalLabel, {
          step_id: step.id,
          action: step.action_type,
          resource: step.resource,
          reason: pepResponse.message,
          decision_reason: pepResponse.decision_reason,
          status_code: pepResponse.status_code,
        });

        // Autopilot records violation
        defaultAutopilot.recordViolation(plan.agent_class, pepResponse.message);

        // Check if rollback needed
        if (pepResponse.rollback_id) {
          defaultPepFramework.rollbackSnapshot(pepResponse.rollback_id);
          defaultAutopilot.recordRollback(plan.agent_class);
          await defaultCausalAudit.logEvent(AuditEventType.ROLLBACK_TRIGGERED, stepCausalLabel, {
            snapshot_id: pepResponse.rollback_id,
            reason: "Policy violation occurred during step execution",
          });
        }

        const failedResult: StepExecutionResult = {
          step_id: step.id,
          step_description: step.description,
          action_type: step.action_type,
          resource: step.resource || "",
          success: false,
          error: pepResponse.message,
          duration_ms: stepDuration,
          token_valid: tokenVerification.valid,
          pep_response: pepResponse,
          causal_event_id: auditEvt.event_id,
        };

        run.step_results.push(failedResult);
        run.status = "blocked";
        run.error = `Execution blocked at ${step.id}: ${pepResponse.message}`;
        run.end_time = Date.now();
        onStepUpdate?.({ ...run });
        return run;
      }

      // Step succeeded!
      const auditEvt = await defaultCausalAudit.logEvent(AuditEventType.ACTION_EXECUTED, stepCausalLabel, {
        step_id: step.id,
        action: step.action_type,
        resource: step.resource,
        pep_type: pepType,
        rollback_id: pepResponse.rollback_id,
        duration_ms: stepDuration,
      });

      defaultAutopilot.recordSuccess(plan.agent_class);

      const successResult: StepExecutionResult = {
        step_id: step.id,
        step_description: step.description,
        action_type: step.action_type,
        resource: step.resource || "",
        success: true,
        output: pepResponse.message,
        duration_ms: stepDuration,
        token_valid: tokenVerification.valid,
        pep_response: pepResponse,
        causal_event_id: auditEvt.event_id,
      };

      run.step_results.push(successResult);
      onStepUpdate?.({ ...run });

      // Artificial short pacing so user can visually witness the execution flow
      await new Promise((resolve) => setTimeout(resolve, 350));
    }

    run.status = "completed";
    run.end_time = Date.now();
    onStepUpdate?.({ ...run });
    return run;
  }
}

export const defaultAgentRunner = new AgentRunner();
