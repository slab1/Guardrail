# Guardrail: Agent Authorization & Safety Operating System

Guardrail is the authorization and safety layer for intelligent operating systems and autonomous AI agents. Built with React 18, Vite, TypeScript, and Tailwind CSS.

## Core Features & Architecture

1. **Intent & Plan Studio**:
   - Compiles natural language goals into static, verifiable steps
   - Categorizes actuator actions into `read`, `write`, `execute`, and `admin`
   - Binds ephemeral Ed25519-signed capability tokens per step
   - Provides reference scenarios: Safe Workspace Refactor, DevOps Build, Red-Team Adversarial Injection, Data Analysis

2. **Graduated Autonomy Ladder (L0–L3) & Consent Management**:
   - **L0 (Read-Only Observer)**: Blocks file writes, shell execution, and admin operations
   - **L1 (Supervised)**: Read/write permitted with automated LSFS snapshot and instant rollback
   - **L2 (Semi-Autonomous)**: Shell execution allowed in isolated MicroVMs; sensitive operations require HITL
   - **L3 (Autonomous)**: Autonomous operations with background audit logging and closed-loop autopilot degradation
   - Interactive Plan Diff and "Explain Deny" policy diagnostics

3. **PEP Fleet (Policy Enforcement Points)**:
   - **PEP-MCP**: Intercepts Model Context Protocol tool invocations, mapping them to permission levels
   - **PEP-FS (LSFS)**: Semantic filesystem with pre-mutation snapshots and zero-loss time-travel rollback
   - **PEP-Exec**: Firecracker microVM hardware isolation (vCPU/RAM bounds, Seccomp BPF filters)
   - **PEP-Net**: Default-deny outbound egress proxy with domain allowlisting and Bearer secret masking

4. **Causal Audit Chain (Kernel-level eBPF)**:
   - Cryptographic SHA-256 hash-chained immutable decision ledger
   - Causal labels attributing host-level events back to signed user intent
   - One-click cryptographic chain integrity verification and tamper detection simulator

5. **Autopilot Closed-Loop Trust Engine**:
   - Empirical scoring (0.0–100.0) based on incident history
   - Automatic elevation or demotion across the autonomy ladder

6. **OpenID Foundation AuthZEN & SPIFFE Workload Identity**:
   - Standard AuthZEN PDP evaluation interface (Subject, Resource, Action, Context)
   - Cryptographically attested SPIFFE IDs (`spiffe://guardrail.internal/agent/...`)

7. **Formal Verification & Regulatory Compliance**:
   - VEPA-style symbolic safety rules with SMT invariant solver and automated patch proposer
   - Continuous compliance mapping across EU AI Act (Articles 14 & 15), NIST AI RMF, ISO 42001, and SOC 2 Type II

## Getting Started

```bash
# Install dependencies
npm install

# Start development server on port 3000
npm run dev

# Build production bundle
npm run build
```
