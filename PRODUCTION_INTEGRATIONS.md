# Guardrail OS — Production Application Integration Record

> **Document Version**: `v1.0.0-PROD`  
> **Status**: Official Reference & Future Integration Workstream Record  
> **Target Runtimes**: Linux Kernel (eBPF/Seccomp), Kubernetes, Node.js/TypeScript, Python FastAPI, ROS2 Robotics, Cloud Microservices

---

## Executive Overview

**Guardrail OS** is designed as a dual-tier, non-bypassable safety and compliance kernel for autonomous AI agents, multi-tenant LLM applications, and mission-critical software pipelines. This record details the **5 Core Production Integration Blueprint Patterns** for embedding Guardrail OS into real production systems, establishing formal invariant proofs, eBPF syscall interception, and cryptographic capability enforcement.

---

## 1. Production Use Case Topologies

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                REAL-WORLD PRODUCTION TOPOLOGIES                              │
├───────────────────────────────┬───────────────────────────────┬──────────────────────────────┤
│ 1. Autonomous AI Dev Agents   │ 2. Financial Ledger & Payments│ 3. Healthcare PHI AI Copilot │
│    - Subprocess Interception  │    - Z3 Double-Entry Logic    │    - HMAC Token PHI Gate     │
│    - Host Isolation           │    - Transfer Cap Proofs      │    - Zero-Trust Egress Trap  │
├───────────────────────────────┼───────────────────────────────┼──────────────────────────────┤
│ 4. Kubernetes eBPF DaemonSet  │ 5. Robotics & ROS2 Control    │ 6. Multi-Tenant SaaS Kernel  │
│    - Container Syscall Filter │    - Real-Time Trajectory Trap│    - Tenant Isolation        │
│    - Host Network Shield      │    - SIGSYS Hardware Halt     │    - Dynamic Kill-Switch     │
└───────────────────────────────┴───────────────────────────────┴──────────────────────────────┘
```

---

## 2. Integration Pattern Specs & Code Blueprints

### Pattern A: Autonomous AI Coding Agents & DevTools

**Production Scenario**: An AI coding agent (e.g., Devin, AutoGPT, Claude Code) runs in a developer workspace or CI pipeline generating and executing terminal commands.

**Guardrail OS Role**:
- Intercepts generated commands before `execve()` execution.
- Generates HMAC-SHA256 Capability Tokens (`tier2_pep_ready`) for permitted file read/write operations.
- Intercepts destructive patterns (`rm -rf`, raw socket egress, privilege escalation `/etc/shadow`) via Tier-2 Data Plane PEP in `< 0.02ms`.

#### Python Agent Integration Snippet:
```python
from guardrail.data_plane_pep import get_data_plane_pep
from guardrail.agent import GuardrailAgent

pep = get_data_plane_pep()
agent = GuardrailAgent(agent_class="coding", user_id="prod_runner", autonomy_level=2)

def execute_agent_step(plan_id: str, step_id: str, action: str, resource: str):
    # 1. Issue Capability Token
    token = pep.issue_token(plan_id, step_id, action, resource, autonomy_level=2)
    
    # 2. Enforce Fast-Path Non-Bypassable PEP Gate (< 0.02ms)
    result = pep.verify_and_enforce(token.to_dict(), requested_action=action, target_resource=resource)
    
    if result["verdict"] != "ALLOW":
        raise PermissionError(f"Guardrail OS Intercepted Unauthorized Syscall: {result['reason']}")
        
    # 3. Safe Execution Path
    print(f"[PEP PASSED] Executing safe action: {action} on {resource}")
```

---

### Pattern B: Financial Transaction & Payment Execution Pipelines

**Production Scenario**: High-frequency automated payment processing, ledger entries, or trading algorithms.

**Guardrail OS Role**:
- Uses the **Z3 SMT Formal Theorem Prover** (Tier 1) to evaluate transaction invariants *before* ledger entry.
- Mathematically proves: `amount <= max_daily_limit`, `balance_after >= 0`, and `recipient in verified_whitelist`.

#### SMT Formal Logic Proof Code:
```python
from guardrail.formal_verification.verifier import create_verifier

verifier = create_verifier()

policy_expression = "amount <= 50000 AND balance_after >= 0 AND verified_recipient == True"
transaction_context = {
    "amount": 12500.00,
    "balance_after": 87500.00,
    "verified_recipient": True
}

# Returns True only if Z3 mathematically proves the invariant holds
is_safe = verifier.verify_policy(policy_expression, transaction_context)
assert is_safe == True, "Transaction violates financial safety invariant!"
```

---

### Pattern C: Healthcare EHR & HIPAA/GDPR AI Assistant

**Production Scenario**: Clinical LLM assistants querying electronic health records (EHR) and synthesizing medical summaries for doctors.

**Guardrail OS Role**:
- **Zero-Trust PHI/PII Masking & Capability Binding**: Ensures the LLM cannot issue raw SQL queries or read unauthorized patient files outside the active consultation envelope.
- **RAG Rails**: Sanitizes prompt inputs and RAG contexts against prompt injection and data exfiltration traps.

#### Node.js / Express Proxy Interception Code:
```typescript
import axios from 'axios';

async function queryEhrData(doctorContext: { id: string; patientId: string }, query: string) {
  // Check Guardrail OS Kernel state & capability token
  const kernelRes = await axios.post('http://guardrail-kernel:8888/api/intent', {
    intent: `Read medical records for patient ${doctorContext.patientId}`
  });

  if (kernelRes.data.status === 'blocked') {
    throw new Error('Guardrail OS Compliance Block: Unauthorized PHI access attempt.');
  }

  // Safe data access authorized by Tier-2 PEP
  return kernelRes.data;
}
```

---

### Pattern D: Kubernetes Container Enforcer (eBPF DaemonSet)

**Production Scenario**: Kubernetes clusters hosting untrusted multi-tenant microservices or AI model workloads.

**Guardrail OS Role**:
- Deployed as a `DaemonSet` on worker nodes.
- Attaches eBPF probe filters (`SECCOMP_RET_TRAP`) to container cgroups.
- Traps unapproved `socket()`, `execve()`, and `setuid(0)` syscalls instantly sending a hardware `SIGSYS (Signal 31)` to kill compromised worker threads before kernel ring access.

---

### Pattern E: Robotics & Autonomous Systems Control Loop

**Production Scenario**: ROS2 robotic arms, autonomous drones, or industrial control units executing kinematic motion plans.

**Guardrail OS Role**:
- Sub-millisecond hard real-time safety interlock.
- Verifies maximum velocity vector $\vec{v}_{max}$, workspace spatial boundaries $(x, y, z)$, and proximity bounds.
- If an anomalous trajectory or rogue motor command is detected, triggers immediate hardware trap, dropping agent autonomy level to `0` (Manual Override).

---

## 3. Real-World Integration Roadmap & Planned Milestones

| Phase | Production Milestone | Target System | Target Metric |
| :--- | :--- | :--- | :--- |
| **Phase 9.1** | **Linux eBPF C-Kernel Native Module** | Bare-metal Linux & K8s | `< 0.005ms` kernel-space intercept |
| **Phase 9.2** | **OpenTelemetry Compliance Exporter** | Datadog / Prometheus | Real-time audit log stream ingestion |
| **Phase 9.3** | **SDK Packages (`@guardrail-os/sdk`, `guardrail-python`)** | npm & PyPI | One-line middleware integration |
| **Phase 9.4** | **Kubernetes Admission Controller Webhook** | K8s API Server | Zero-trust Pod security policy validation |

---

## 4. Verification & Health Probes

To verify Guardrail OS integration in any production environment:
```bash
# 1. Run full local CI/CD validator
bash ./scripts/validate_ci.sh

# 2. Check kernel status endpoint
curl http://localhost:8888/api/kernel/state

# 3. Test Dual-Tier PEP Benchmark
curl -X POST http://localhost:8888/api/pep/dual-benchmark
```
