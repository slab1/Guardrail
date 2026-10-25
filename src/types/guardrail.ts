// Guardrail core domain types & data models

export enum AutonomyLevel {
  L0 = 0, // Read-Only / Observer
  L1 = 1, // Supervised: Read/Write, Rollback-protected
  L2 = 2, // Semi-Autonomous: Read/Write/Execute, no admin
  L3 = 3, // Full Autonomy: Self-governing with background audit
}

export const AUTONOMY_LEVEL_NAMES: Record<AutonomyLevel, string> = {
  [AutonomyLevel.L0]: "L0 - Read-Only Observer",
  [AutonomyLevel.L1]: "L1 - Supervised (Rollback Enabled)",
  [AutonomyLevel.L2]: "L2 - Semi-Autonomous",
  [AutonomyLevel.L3]: "L3 - Full Autonomy",
};

export const AUTONOMY_DESCRIPTIONS: Record<AutonomyLevel, string> = {
  [AutonomyLevel.L0]: "Inspects files and query APIs only. All writes, network mutations, and shell executions are blocked.",
  [AutonomyLevel.L1]: "Can read and write files with automated LSFS snapshot/rollback. Shell commands require explicit human sign-off.",
  [AutonomyLevel.L2]: "Can read, write, execute safe scripts and query allowed endpoints. Sensitive admin operations require consent.",
  [AutonomyLevel.L3]: "Autonomous execution across tools. Continuous causal audit logging and real-time autopilot trust degradation on faults.",
};

export type ToolCategory = "read" | "write" | "execute" | "admin";

export const CATEGORY_REQUIRED_LEVEL: Record<ToolCategory, AutonomyLevel> = {
  read: AutonomyLevel.L0,
  write: AutonomyLevel.L1,
  execute: AutonomyLevel.L2,
  admin: AutonomyLevel.L3,
};

export const TOOL_CATEGORY_MAP: Record<string, ToolCategory> = {
  file_read: "read",
  file_list: "read",
  file_search: "read",
  http_get: "read",
  api_query: "read",
  file_write: "write",
  file_delete: "write",
  file_modify: "write",
  http_post: "write",
  http_put: "write",
  http_delete: "write",
  shell_command: "execute",
  shell_exec: "execute",
  script_run: "execute",
  container_spawn: "execute",
  admin_tool: "admin",
  credential_rotate: "admin",
  grant_privilege: "admin",
  system_reboot: "admin",
};

export interface PlanStep {
  id: string;
  description: string;
  action_type: string;
  resource?: string;
  category: ToolCategory;
  required_level: AutonomyLevel;
  reversible: boolean;
  pre_conditions?: string[];
  post_conditions?: string[];
  risk_level: "low" | "medium" | "high";
}

export interface ValidatedPlan {
  id: string;
  intent: string;
  description: string;
  agent_class: string;
  user_id: string;
  autonomy_level: AutonomyLevel;
  steps: PlanStep[];
  model_required: string;
  created_at: string;
  validation_errors: string[];
  is_valid: boolean;
  step_tokens: Record<string, string>; // step_id -> token string
  plan_token?: string;
  risk_score: "low" | "medium" | "high";
}

export enum TokenType {
  PLAN = "plan",
  STEP = "step",
}

export interface TokenPayload {
  token_type: TokenType;
  plan_id: string;
  step_id?: string;
  intent: string;
  agent_class: string;
  user_id: string;
  autonomy_level: AutonomyLevel;
  issued_at: number;
  expires_at: number;
  nonce: string;
  signature?: string;
}

export enum ConsentStatus {
  PENDING = "pending",
  APPROVED = "approved",
  DENIED = "denied",
  EXPIRED = "expired",
}

export interface ConsentRequest {
  plan_id: string;
  plan_description: string;
  steps_summary: {
    step_id: string;
    description: string;
    action_type: string;
    resource?: string;
    risk_level: "low" | "medium" | "high";
    category: ToolCategory;
  }[];
  risk_level: "low" | "medium" | "high";
  requested_at: number;
  expires_at: number;
  status: ConsentStatus;
  user_id: string;
}

export interface ConsentDecision {
  plan_id: string;
  approved: boolean;
  step_approvals: Record<string, boolean>; // step_id -> approved
  conditions: string[];
  decided_at: number;
  decided_by: string;
  explanation?: string;
}

export enum PEPType {
  MCP = "mcp",
  FS = "fs",
  EXEC = "exec",
  NET = "net",
}

export interface PEPRequest {
  pep_type: PEPType;
  action: string;
  resource: string;
  step_token?: string;
  step_id?: string;
  plan_id?: string;
  agent_id: string;
  autonomy_level: AutonomyLevel;
  payload?: Record<string, any>;
}

export interface PEPResponse {
  pep_type: PEPType;
  allowed: boolean;
  status_code: number;
  message: string;
  decision_reason: string;
  rollback_id?: string;
  sanitized_payload?: Record<string, any>;
  timestamp: number;
}

export interface LSFSSnapshot {
  snapshot_id: string;
  timestamp: number;
  path: string;
  original_content: string;
  plan_id: string;
  step_id: string;
}

export interface MicroVMState {
  vm_id: string;
  kernel_path: string;
  vcpus: number;
  memory_mb: number;
  state: "idle" | "running" | "isolated" | "terminated";
  active_execution?: string;
  uptime_seconds: number;
}

export interface NetworkRule {
  id: string;
  pattern: string; // e.g., "*.internal.net", "api.github.com"
  action: "ALLOW" | "DENY" | "INJECT_SECRETS";
  tls_required: boolean;
  description: string;
}

export enum AuditEventType {
  PLAN_SUBMITTED = "PLAN_SUBMITTED",
  PLAN_VALIDATED = "PLAN_VALIDATED",
  CONSENT_REQUESTED = "CONSENT_REQUESTED",
  CONSENT_DECIDED = "CONSENT_DECIDED",
  TOKEN_ISSUED = "TOKEN_ISSUED",
  PEP_INTERCEPTED = "PEP_INTERCEPTED",
  ACTION_EXECUTED = "ACTION_EXECUTED",
  POLICY_VIOLATION = "POLICY_VIOLATION",
  ROLLBACK_TRIGGERED = "ROLLBACK_TRIGGERED",
  TRUST_EVALUATED = "TRUST_EVALUATED",
}

export interface CausalLabel {
  label_id: string;
  plan_id: string;
  step_id: string;
  intent: string;
  agent_class: string;
  user_id: string;
  autonomy_level: AutonomyLevel;
  issued_at: number;
  signature: string;
}

export interface AuditEvent {
  event_id: string;
  timestamp: number;
  event_type: AuditEventType;
  causal_label: CausalLabel;
  details: Record<string, any>;
  previous_hash: string;
  hash: string;
}

export enum TrustLevel {
  LOCKED = 0,      // L0
  PROTECTED = 1,   // L1
  UNRESTRICTED = 2, // L2
  AUTONOMOUS = 3,  // L3
}

export interface TrustProfile {
  agent_id: string;
  user_id: string;
  agent_class: string;
  base_autonomy_level: AutonomyLevel;
  current_trust_level: TrustLevel;
  trust_score: number; // 0.0 to 100.0
  total_events: number;
  violation_count: number;
  success_count: number;
  rollback_count: number;
  last_evaluation: number;
  elevation_history: {
    timestamp: number;
    old_level: TrustLevel;
    new_level: TrustLevel;
    reason: string;
    score: number;
  }[];
}

export interface AuthZENDecisionRequest {
  subject: {
    type: "user" | "agent" | "workload";
    id: string;
    spiffe_id?: string;
    agent_class?: string;
    autonomy_level?: number;
  };
  resource: {
    type: "file" | "api" | "process" | "mcp_tool";
    id: string;
  };
  action: {
    name: string;
    category?: ToolCategory;
  };
  context: {
    plan_id?: string;
    step_id?: string;
    intent?: string;
    risk_level?: string;
    token_present?: boolean;
  };
}

export interface AuthZENDecisionResponse {
  decision: "PERMIT" | "DENY" | "INDETERMINATE";
  evaluations: {
    policy_id: string;
    rule_name: string;
    passed: boolean;
    reason: string;
  }[];
  timestamp: number;
  latency_ms: number;
}

export interface SPIFFEIdentity {
  spiffe_id: string;
  trust_domain: string;
  workload: string;
  agent_class: string;
  sponsor_user: string;
  issued_at: number;
  cert_fingerprint: string;
}

export interface FormalPolicyRule {
  id: string;
  name: string;
  type: "SAFETY" | "SECURITY" | "RESOURCE" | "COMPLIANCE";
  expression: string;
  enabled: boolean;
  remediation: string;
}

export interface ComplianceControl {
  control_id: string;
  framework: "EU_AI_ACT" | "NIST_AI_RMF" | "ISO_42001" | "SOC2";
  title: string;
  description: string;
  status: "IMPLEMENTED" | "PARTIAL" | "NOT_IMPLEMENTED";
  guardrail_module: string;
  evidence: string;
}

export interface StepExecutionResult {
  step_id: string;
  step_description: string;
  action_type: string;
  resource: string;
  success: boolean;
  output?: string;
  error?: string;
  duration_ms: number;
  token_valid: boolean;
  pep_response: PEPResponse;
  causal_event_id?: string;
}

export interface PlanExecutionRun {
  run_id: string;
  plan: ValidatedPlan;
  status: "idle" | "validating" | "awaiting_consent" | "executing" | "completed" | "blocked" | "rolled_back";
  current_step_index: number;
  step_results: StepExecutionResult[];
  start_time?: number;
  end_time?: number;
  error?: string;
}
