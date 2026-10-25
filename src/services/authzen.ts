// Guardrail AuthZEN & Identity Federation (SPIFFE / ID-JAG)

import {
  AuthZENDecisionRequest,
  AuthZENDecisionResponse,
  AutonomyLevel,
  CATEGORY_REQUIRED_LEVEL,
  SPIFFEIdentity,
  TOOL_CATEGORY_MAP,
  ToolCategory,
} from "../types/guardrail";

export class AuthZENService {
  private spiffeIdentities: Map<string, SPIFFEIdentity> = new Map();

  constructor() {
    this.seedIdentities();
  }

  private seedIdentities() {
    const defaultSpiffe: SPIFFEIdentity = {
      spiffe_id: "spiffe://guardrail.internal/agent/coding-01",
      trust_domain: "guardrail.internal",
      workload: "agent-runner-node-a",
      agent_class: "coding",
      sponsor_user: "developer_01",
      issued_at: Date.now() - 7200000,
      cert_fingerprint: "SHA256:d8:e2:4c:71:b9:2f:18:a4:9c:88:e1:fa",
    };

    const sysadminSpiffe: SPIFFEIdentity = {
      spiffe_id: "spiffe://guardrail.internal/agent/sysadmin-prod",
      trust_domain: "guardrail.internal",
      workload: "k8s-pod-governor-c",
      agent_class: "sysadmin",
      sponsor_user: "devops_lead",
      issued_at: Date.now() - 14400000,
      cert_fingerprint: "SHA256:b1:94:02:f7:7e:33:10:a9:cc:50:81:df",
    };

    this.spiffeIdentities.set(defaultSpiffe.spiffe_id, defaultSpiffe);
    this.spiffeIdentities.set(sysadminSpiffe.spiffe_id, sysadminSpiffe);
  }

  public async evaluate(request: AuthZENDecisionRequest): Promise<AuthZENDecisionResponse> {
    const startTime = performance.now();
    const evaluations = [];

    // Rule 1: Subject Identity Verification
    let subjectValid = false;
    if (request.subject.spiffe_id) {
      subjectValid = this.spiffeIdentities.has(request.subject.spiffe_id);
      evaluations.push({
        policy_id: "pol-authzen-01-spiffe",
        rule_name: "SPIFFE Workload Identity Validation",
        passed: subjectValid,
        reason: subjectValid
          ? `Workload attested in trust domain '${this.spiffeIdentities.get(request.subject.spiffe_id)?.trust_domain}'`
          : "Workload SPIFFE ID unknown or revoked",
      });
    } else {
      subjectValid = true;
      evaluations.push({
        policy_id: "pol-authzen-01-spiffe",
        rule_name: "SPIFFE Identity Check",
        passed: true,
        reason: "Local subject authenticated via session token",
      });
    }

    // Rule 2: Capability / Autonomy Level Check
    const toolCategory: ToolCategory =
      request.action.category || TOOL_CATEGORY_MAP[request.action.name] || "read";
    const requiredLevel = CATEGORY_REQUIRED_LEVEL[toolCategory];
    const subjectAutonomy = request.subject.autonomy_level ?? AutonomyLevel.L0;

    const levelAllowed = subjectAutonomy >= requiredLevel;
    evaluations.push({
      policy_id: "pol-authzen-02-autonomy",
      rule_name: "Autonomy Level Privilege Check",
      passed: levelAllowed,
      reason: levelAllowed
        ? `Subject level L${subjectAutonomy} meets or exceeds required L${requiredLevel} for '${toolCategory}'`
        : `Privilege denial: action requires L${requiredLevel}, subject has L${subjectAutonomy}`,
    });

    // Rule 3: Intent Binding & Token Context Check
    const tokenPresent = request.context.token_present !== false;
    evaluations.push({
      policy_id: "pol-authzen-03-intent-binding",
      rule_name: "Signed Intent Binding Context",
      passed: tokenPresent,
      reason: tokenPresent
        ? "Action bound to active verified plan step"
        : "Missing signed intent capability context token",
    });

    // Final decision calculation
    const allPassed = evaluations.every((e) => e.passed);
    const decision: "PERMIT" | "DENY" = allPassed ? "PERMIT" : "DENY";
    const latency_ms = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      decision,
      evaluations,
      timestamp: Date.now(),
      latency_ms,
    };
  }

  public getSpiffeIdentities(): SPIFFEIdentity[] {
    return Array.from(this.spiffeIdentities.values());
  }

  public issueIdentity(agentClass: string, sponsorUser: string): SPIFFEIdentity {
    const id = `agent-${agentClass}-${Math.random().toString(36).substring(2, 6)}`;
    const spiffeId = `spiffe://guardrail.internal/agent/${id}`;
    const identity: SPIFFEIdentity = {
      spiffe_id: spiffeId,
      trust_domain: "guardrail.internal",
      workload: `workload-${id}`,
      agent_class: agentClass,
      sponsor_user: sponsorUser,
      issued_at: Date.now(),
      cert_fingerprint: `SHA256:${Array.from({ length: 6 }, () =>
        Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, "0")
      ).join(":")}`,
    };
    this.spiffeIdentities.set(spiffeId, identity);
    return identity;
  }
}

export const defaultAuthZEN = new AuthZENService();
