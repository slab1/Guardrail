# Guardrail OS - Operational User Manual & Reference Guide

Welcome to **Guardrail OS**, the high-performance, formal-methods-backed security kernel and deterministic Policy Enforcement Point (PEP) engine designed for autonomous AI agent fleets.

---

## 1. System Overview & Architecture

Guardrail OS enforces non-bypassable safety invariants using **The Dual-Tier Model**:

```
+-----------------------------------------------------------------------+
|                       TIER 1: CONTROL PLANE                           |
|  - Human Intent Translation & Symbolic Policy AST Generation           |
|  - Z3 SMT Theorem Prover (VEPA Formal Logic Invariant Verification)   |
|  - Dual-LLM Semantic Guard & RAG Injection Rails                      |
|  - Issues Unforgeable Cryptographic Capability Tokens                 |
+-----------------------------------------------------------------------+
                                   |
                                   v (Linear HMAC Tokens & Seccomp Profiles)
+-----------------------------------------------------------------------+
|                    TIER 2: DATA PLANE PEP                             |
|  - Hardware-Adjacent Fast-Path Execution (<0.02ms / 19 microseconds)  |
|  - Constant-Time HMAC-SHA256 Token Signature Verification             |
|  - Linear Nonce Anti-Replay Registry (Single-Use Tokens)               |
|  - Non-Bypassable eBPF / Seccomp Syscall Filter (SIGSYS 31 Trapping)  |
+-----------------------------------------------------------------------+
```

---

## 2. Navigating the 9 Kernel Console Views

### 1. Intent Studio (`/studio`)
- **Purpose**: Translates natural language prompt intents into formal agent action plans.
- **Key Features**:
  - Live Intent Processing & Formal VEPA Logic Check.
  - Interactive **Cryptographic Token Inspector**: Decodes `gr_*` capability tokens, JWTs, and Tier-2 JSON objects.
  - **Policy Check Modal**: Explains denied steps and suggests autonomy elevation paths.

### 2. Dual-Tier Architecture (`/dualtier`)
- **Purpose**: Live topology visualizer comparing Control Plane vs. Data Plane PEP.
- **Key Features**:
  - **Live Cross-Tier Benchmark**: Demonstrates microsecond Data Plane fast-path (<0.02ms) vs. Control Plane compilation (~40ms), proving a 1,000x+ speedup.
  - **Interactive eBPF Syscall Attack Injection Lab**: Inject live simulated attacks:
    - Rogue Shell Execution (`execve /bin/sh`)
    - Raw TCP Egress Exfiltration (`socket(AF_INET, SOCK_RAW)`)
    - Host Configuration Override (`openat /etc/shadow`)
    - Root Privilege Escalation (`setuid 0`)
  - Displays hardware trap signal `SIGSYS (31)`, Seccomp filter rules, eBPF ring buffer event IDs, and kernel register dumps (`%rax`, `%rdi`, `%rsi`, `%rip`).

### 3. Agent ACLs & Emergency Kill-Switch (`/incidents`)
- **Purpose**: Multi-tenant agent isolation and immediate threat containment.
- **Key Features**:
  - **Multi-Tenant Roster**: Switch between `DevOps Agent` (L2), `Finance Agent` (L1), `Customer Care` (L0), and `Autonomous Synthesizer` (L3).
  - **Emergency Kill-Switch**: One-click full quarantine that revokes all active capability tokens, sets agent trust score to `0.0`, freezes autonomy to `L0`, and logs an emergency audit trace.
  - **Administrative Restore**: Lift quarantine and restore operational status after operator review.

### 4. PEP Fleet Telemetry (`/pep`)
- **Purpose**: Monitors distributed microsecond PEP enforcement gates and sandbox runtime profiles.
- **Key Features**:
  - Seccomp BPF profiles per autonomy level (L0-L3).
  - Copy-on-Write (CoW) filesystem staging stats and Firecracker MicroVM container states.

### 5. AuthZEN / SPIFFE Console (`/authzen`)
- **Purpose**: IETF AuthZEN standard decision engine and SPIFFE Workload Identity verification.
- **Key Features**:
  - Interactive Subject/Resource/Action decision tester returning `PERMIT`, `DENY`, or `INDETERMINATE` verdicts.

### 6. Autopilot Closed-Loop Engine (`/autopilot`)
- **Purpose**: Real-time agent trust scoring (0.0% to 100.0%) with automated risk dampening.
- **Key Features**:
  - Dynamic trust degradation upon PEP traps, policy violations, or anomaly triggers.
  - Score reset and baseline trust calibration controls.

### 7. Consent Matrix (`/consent`)
- **Purpose**: Human-in-the-Loop (HITL) consent review and Graduated Autonomy Ladder.
- **Key Features**:
  - Granular step-by-step approval diffs.
  - Autonomy level selector (L0 Read-Only, L1 Supervised, L2 Semi-Autonomous, L3 Full Autonomy).
  - Direct persistence to `/api/consent/decide` and local storage.

### 8. Causal Audit Trail (`/audit`)
- **Purpose**: Immutable event stream recording all intent submissions, logic verdicts, PEP traps, and kill-switch triggers.
- **Key Features**:
  - Deterministic trace hash IDs.
  - Filterable by `ALL` or `VIOLATIONS`.
  - One-click **Cloud Sync to Firebase Firestore** and JSON export.

### 9. Governance & Compliance (`/compliance`)
- **Purpose**: Formal policy registry and automated evidence mapping for EU AI Act and NIST AI RMF.
- **Key Features**:
  - **Symbolic Policy Editor**: Draft, test, and deploy custom VEPA DSL formal safety invariants.
  - **Export Compliance Evidence Bundle**: Generates official JSON audit evidence packages for external compliance auditors.

---

## 3. Operational Playbooks

### Playbook A: Registering a New Formal Safety Invariant
1. Open **Governance** (`/compliance`).
2. Switch to **Policy Registry** tab and click **Register New Invariant**.
3. Enter the **Name**, **Description**, and **VEPA DSL Expression** (e.g., `action == 'network_egress' IMPLIES resource.startswith('https://api.internal/')`).
4. Click **Simulate** to test against sample contexts.
5. Click **Save & Deploy** to persist the invariant into `kernel_storage.json`.

### Playbook B: Inspecting a Cryptographic Capability Token
1. Open **Intent Studio** (`/studio`).
2. Submit an intent or view an existing plan step.
3. Click the token badge (e.g., `gr_tok_...`).
4. The **Token Inspector Modal** decodes the HMAC-SHA256 signature, linear nonce, issued time, expiration window, bound action, and resource envelope.

### Playbook C: Executing an Emergency Agent Containment
1. If an agent exhibits anomalous behavior or triggers a security alert:
2. Open **Agent ACLs & Kill-Switch** (`/incidents`).
3. Locate the target tenant or select it in the **Manual Emergency Containment Trigger**.
4. Enter the containment justification and click **EXECUTE CONTAINMENT PLAYBOOK**.
5. All issued capability tokens for that tenant are invalidated instantly, trust drops to `0.0`, and all system mutations are blocked.

---

## 4. API Endpoint Quick Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/intent` | `POST` | Submits natural language intent, compiles plan, and issues Data Plane tokens. |
| `/api/pep/verify-token` | `POST` | Microsecond fast-path token verification & Seccomp gate (<0.02ms). |
| `/api/pep/attack-inject` | `POST` | Injects simulated syscall attack (`execve`, `socket`, `setuid`). |
| `/api/pep/dual-benchmark` | `POST` | Runs live cross-tier latency benchmark comparing Tier 1 vs Tier 2. |
| `/api/agents/tenants` | `GET` | Lists multi-tenant agent rosters and active capability statuses. |
| `/api/agents/switch` | `POST` | Switches active agent persona and autonomy context. |
| `/api/incidents/kill-switch` | `POST` | Executes emergency kill-switch and places tenant in quarantine. |
| `/api/incidents/restore` | `POST` | Lifts quarantine and restores agent operational status. |
| `/api/policies/templates` | `GET`/`POST` | Fetches or registers custom VEPA DSL formal safety invariants. |
| `/api/compliance/export` | `GET` | Exports complete EU AI Act & NIST AI RMF compliance evidence bundle. |
| `/api/audit/logs` | `GET` | Fetches immutable causal audit log traces. |

---

*Guardrail OS Kernel v2.4 • Sub-10ms Non-Bypassable PEP Standard*
