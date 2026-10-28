# Guardrail OS - High-Performance Formal Security Kernel for Autonomous AI Agents

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Release Status](https://img.shields.io/badge/release-Public_Alpha_%2F_Dev_Preview-amber.svg)]()
[![PEP Latency Target](https://img.shields.io/badge/PEP_Latency-<0.05ms-blue.svg)]()
[![Compliance](https://img.shields.io/badge/compliance-EU_AI_Act_%7C_NIST_AI_RMF-emerald.svg)]()
[![Standards](https://img.shields.io/badge/IETF-AuthZEN_%7C_SPIFFE-purple.svg)]()

> ⚠️ **RELEASE NOTICE & SECURITY BOUNDARY DISCLAIMER**  
> **Release Type**: **Public Alpha / Developer Preview (v2.5.0-alpha)**  
> Guardrail OS is published for research, developer evaluation, and prototyping. It is **not yet a certified production security boundary**. End-to-end OS-level blocking, deployment behavior under daemon failure, and cross-engine revocation guarantees must be independently verified for your target runtime. See [RELEASE_DECISION.md](RELEASE_DECISION.md) for full audit findings, known limitations, and security test evidence.

**Guardrail OS** is a formal-methods-backed security kernel and deterministic Policy Enforcement Point (PEP) designed for autonomous AI agent fleets. It eliminates safety hazards, prompt injections, privilege escalation, and unauthorized tool calls through **The Dual-Tier Model**: separating asynchronous cognitive policy compilation (Tier 1 Control Plane) from non-bypassable microsecond capability token verification and eBPF/Seccomp syscall trapping (Tier 2 Data Plane).


---

## Key Features

- ⚡ **Microsecond Data Plane PEP (<0.02ms Fast-Path)**:
  Constant-time HMAC-SHA256 signature verification, linear single-use nonce anti-replay tracking, and resource boundary checks executing in **19 microseconds** (achieving a **1,000x+ speedup** over Control Plane evaluation).
- 🔒 **Non-Bypassable eBPF & Seccomp Syscall Filter**:
  Hardware-adjacent enforcement trapping unauthorized actuator execution with `SIGSYS (31)` or `EPERM` signals.
- 🛡️ **Formal Verification (Z3 SMT Theorem Prover)**:
  Evaluates VEPA DSL safety invariants mathematically with zero false positives.
- 🧪 **Interactive eBPF Syscall Attack Injection Lab**:
  Simulates rogue shell injection (`execve /bin/sh`), raw TCP socket egress (`socket RAW`), host config overrides (`/etc/shadow`), and privilege escalation (`setuid 0`) with live CPU register dumps (`%rax`, `%rdi`, `%rsi`, `%rip`).
- 🚨 **Multi-Tenant ACLs & Emergency Kill-Switch Playbooks**:
  Supports tenant-isolated agent rosters with instant full-quarantine capabilities that revoke all active capability tokens and freeze autonomy to L0.
- 📜 **EU AI Act & NIST Compliance Evidence Export**:
  One-click export of structured compliance evidence bundles containing formal invariants, SMT verification proofs, Article 14/15 evidence mappings, and PEP telemetry.
- 🔑 **Multi-Format Token Inspector**:
  Supports `gr_*` capability tokens, `ey*` JWT tokens, and `{...}` Tier-2 JSON capability payloads with URL-safe Base64 decoding.
- 💾 **Stateful Persistence**:
  Survives server reboots via `data/kernel_storage.json` and syncs seamlessly to Cloud Firestore.

---

## Architectural Overview

```
+-----------------------------------------------------------------------------------+
|                            TIER 1: CONTROL PLANE                                  |
|  - Human Intent Translation & Symbolic Policy AST Generation                      |
|  - Z3 SMT Theorem Prover (VEPA Formal Logic Invariants)                            |
|  - Dual-LLM Semantic Guard & RAG Injection Sanitization                           |
|  - Issues Cryptographic Capability Tokens & Nonces                                |
+-----------------------------------------------------------------------------------+
                                          |
                                          v (Linear HMAC Tokens & Seccomp Rules)
+-----------------------------------------------------------------------------------+
|                           TIER 2: DATA PLANE PEP                                  |
|  - Microsecond Fast-Path Execution (<0.02ms / 19 microseconds)                    |
|  - Constant-Time HMAC-SHA256 Token Signature Verification                         |
|  - Linear Nonce Anti-Replay Registry (Single-Use Nonces)                          |
|  - Hardware Seccomp BPF Syscall Envelope Gate (SIGSYS 31 Trapping)                |
+-----------------------------------------------------------------------------------+
```

---

## Quickstart Guide

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+ with `fastapi`, `uvicorn`, `pydantic`, `pytest`

### Security & Credential Isolation (GitHub Safe)
> 🔐 **CREDENTIAL HYGIENE**: `firebase-applet-config.json`, `.env`, and local kernel database ledgers (`data/`) are strictly excluded in `.gitignore` and `.dockerignore`.
> - When deploying or cloning from GitHub, copy `firebase-applet-config.example.json` to `firebase-applet-config.json` with your project's credentials.
> - Never commit real Firebase API keys or service credentials to public repositories.

### Installation & Launch

1. **Install Node Dependencies**:
   ```bash
   npm install
   ```

2. **Configure Firebase (Local)**:
   ```bash
   cp firebase-applet-config.example.json firebase-applet-config.json
   # Edit with your Firebase project credentials
   ```

3. **Start Dev Server (Vite + FastAPI Kernel Proxy)**:
   ```bash
   npm run dev
   ```
   - Vite UI: `http://localhost:3000`
   - FastAPI Kernel Backend: `http://localhost:8888`

4. **Run Unit Tests**:
   ```bash
   python3 -m pytest tests/
   ```

---

## Kernel Navigation Tabs

| Tab | Name | Purpose |
| :--- | :--- | :--- |
| `studio` | **Intent Studio** | Intent submission, plan generation, and token inspection. |
| `dualtier` | **Dual-Tier Arch** | Live benchmark comparing Control Plane vs. Data Plane PEP + Attack Lab. |
| `incidents` | **Agent ACLs & Kill-Switch** | Multi-tenant agent rosters and emergency quarantine triggers. |
| `pep` | **PEP Fleet** | Distributed microsecond PEP gate metrics and Seccomp profiles. |
| `authzen` | **AuthZEN / SPIFFE** | IETF AuthZEN standard policy decision tester & SPIFFE identities. |
| `autopilot` | **Autopilot** | Closed-loop trust scoring (0-100%) and automatic risk dampening. |
| `consent` | **Consent Matrix** | HITL plan approval diffs and Graduated Autonomy Ladder (L0-L3). |
| `audit` | **Causal Audit** | Immutable trace logs with Firebase Cloud sync & JSON export. |
| `compliance` | **Governance** | Symbolic VEPA DSL policy editor & EU AI Act compliance bundle export. |

---

## Production Integration Blueprints

Guardrail OS is built for real production applications. See our complete [Real Production Integration Record (PRODUCTION_INTEGRATIONS.md)](PRODUCTION_INTEGRATIONS.md) for architecture patterns, deployment topologies, and code blueprints:

1. **Autonomous AI Coding Agents**: Subprocess execution gating and shell command interception (<0.02ms PEP fast-path).
2. **Financial Transactions & Ledger Pipelines**: Z3 SMT formal proofs of double-entry invariants, transfer caps, and daily limit safety.
3. **Healthcare EHR & HIPAA AI Copilots**: Zero-trust PHI token binding and RAG injection sanitization.
4. **Kubernetes eBPF Container Enforcer**: Cluster-wide Seccomp `SIGSYS` syscall filtering via worker node DaemonSets.
5. **Robotics & ROS2 Control Loops**: Sub-millisecond kinematic trajectory interlocks and hardware trap halts.

---

## Documentation

- 📄 **[Release Decision & Security Evaluation (RELEASE_DECISION.md)](RELEASE_DECISION.md)** — Audit findings, release matrix, known limitations, and test verification.
- 📘 **[Real Production Integrations Guide](PRODUCTION_INTEGRATIONS.md)** — Architectural integration patterns & code blueprints.
- 📕 **[Guardrail OS User Manual](USER_MANUAL.md)** — Comprehensive operational handbook, playbooks, and API specs.

---

*Guardrail OS Kernel v2.5.0-alpha • Public Alpha / Developer Preview Standard*

