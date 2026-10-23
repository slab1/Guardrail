# Guardrail Project Specification

## 1. Overview
Guardrail is the authorization and safety layer for an intelligent operating system. It provides:
- Non-bypassable policy enforcement between LLM agents and actuators (files, shell, network, MCP tools)
- Intent-bound, per-step, short-lived capabilities (instead of session-level permissions)
- Graduated autonomy on a consent ladder
- Causal audit via kernel-level eBPF tracing

## 2. Research Foundation

### 2.1 Academic Architecture
- **AIOS (Mei et al., COLM 2025)**: LLM-as-CPU-core kernel; scheduler/context/memory/storage/tool/access managers; 2.1× agent serving speedup. *Take*: module decomposition, syscall decomposition.
- **LSFS (Shi et al., ICLR 2025)**: Semantic FS layer with semantic syscalls, time/version rollback, NL parser; error reduction 15%→0%. *Take*: `pep-fs` design, rollback for L1 autonomy, parser-with-retry pattern.
- **LLM-as-OS Vision (Ge et al., arXiv 2023)**: LLM=kernel, context=memory, tools=devices, NL=shell. *Take*: roadmap grammar for full intelligent OS.
- **AgentLoupe (Bao et al., arXiv 2026)**: eBPF kernel-resident causal labels, <8% overhead, cross-lineage attribution. *Take*: audit substrate (M5).
- **Trust-boundary Study (Leong, arXiv 2026)**: LLM self‑arbitration not a trust boundary; external reference monitor rejects forged records. *Take*: justification for Guardrail; defines unsolved research track.

### 2.3 Benchmarks (with caveats)
- **OSWorld v1**: 12% (Apr 2024) → 86% (claude‑fable‑5, Aug 2026). Human baseline 72%.
- **OSWorld 2.0** (long‑horizon, median task 1.6 h): best binary 44%, partial 78%.
- **Adversarial study**: 73% OSWorld score achieved solving zero tasks (exploited graders) → audit/eval infrastructure must be isolated from agent environment (non‑negotiable).

### 2.4 Standards (Oct 2026)
- **MCP 2026‑07‑28**: stateless protocol, DCR deprecated → Client ID Metadata Documents, tighter token binding; new Enterprise Managed Authorization extension (ID‑JAG / Cross‑App Access).
- **Consensus 3‑layer identity**: SPIFFE/WIMSE (what is this agent) · OAuth 2.1 (what may it touch) · ID‑JAG (who governs delegation); AuthZEN provides fine‑grained decision API.
- **Five converged primitives**: agent registry, human sponsor binding, short‑lived scoped credentials, MCP‑layer enforcement, runtime (not login‑time) authorization → differentiation now depth and ecosystem.

### 2.5 Market & Competitive Landscape
- **Funding (Apr 2025–Sep 2026)**: AI‑governance total ~25 + 1.02 B follow‑on; Policy Enforcement 689 M across 26 deals (Onyx 113 M, Zenity 125 M, HiddenLayer 100 M, Neo 75 M, Arcade.dev 60 M, Straiker 64 M, AIR Security 50 M, Keycard 38 M, Runlayer 30 M, Token Security, Willow).
- **MCP gateways** (2026): Mintive, Obot, Lunar.dev MCPX, Kong, Traefik Hub, AWS AgentCore, Datawiza, Docker MCP, IBM ContextForge, agentgateway, Peta. Common capabilities: RBAC/ABAC, per‑user OAuth passthrough, rug‑pull protection, SIEM export, IdP federation.
- **Sandboxing**: Firecracker microVMs (gold standard, 125‑150 ms boot, 5 MB), E2B (managed 2B+ sandboxes, 0.000014 s, Apache‑2.0), microsandbox (libkrun), Fly.io Sprites (300 ms checkpoint/restore). GPU passthrough requires Firecracker/KVM; break‑even for self‑hosting E2B ≈ 11 000 sandbox‑hours/month.

### 2.6 Differentiation Matrix
| Capability | Typical gateway | Mintive | Lunar MCPX | Token Sec | Keycard | Guardrail |
|-----------|----------------|---------|-----------|----------|--------|-----------|
| Tool‑level RBAC/ABAC | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Non‑human agent identity | ◐ | ✓ | ◐ | ✓ | ✓ | ✓ (SPIFFE) |
| Short‑lived scoped credentials | ◐ | ✓ | ◐ | ✓ | ✓ | ✓ |
| Per‑plan‑step tokens (not session) | ✗ | ✗ | ◐ | ✗ | ◐ | ✓ |
| Intent‑bound tokens w/ signed intent | ✗ | ✗ | ◐ | ✓ (policy gen) | ✓ (task) | ✓ |
| Plan compiler (intent→static action plan) | ✗ | ✗ | ✗ | ◐ | ✗ | ✓ |
| Graduated autonomy ladder (L0‑L4) | ✗ | ◐ (rules) | ◐ | ✗ | ✗ | ✓ |
| Semantic‑FS rollback integration | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| eBPF causal audit (kernel‑level) | ✗ | ◐ (monitor) | ✗ | ✗ | ✗ | ✓ |
| Autopilot trust scoring (closed loop) | ✗ | ◐ | ✗ | ◐ | ✗ | ✓ |

**Positioning**: Everyone sells gates (RBAC at the door). Guardrail sells supervision — it understands the plan, grants per‑step capabilities, escalates consent by risk, and can prove afterwards what happened and why. “PAM/just‑in‑time access for agents, raised to the OS level.”

---

## 4. Product Definition

### 3.1 Component Stack
```
┌────────────────────────────────────────────────────────────┐
│ Consent UI (plan diff · autonomy ladder · "explain deny")  │
├────────────────────────────────────────────────────────────┤
│ Plan Compiler (intent → static, analyzable action plan)    │
├────────────────────────────────────────────────────────────┤
│ PDP (Cedar policies · risk scoring · AuthZEN interface)    │
│ Token Service (Ed25519 · per‑step · intent‑bound · ≤15 min) │
├────────────────────────────────────────────────────────────┤
│ PEP fleet: pep-mcp │ pep-fs (LSFS) │ pep-exec │ pep-net   │
├────────────────────────────────────────────────────────────┤
│ Sandbox substrate: Firecracker microVMs (agent isolation)  │
├────────────────────────────────────────────────────────────┤
│ Audit: hash‑chained decision log + eBPF causal labels      │
└────────────────────────────────────────────────────────────┘
```

### 3.3 Milestones & Timeline (24 months)

| Phase | Months | Key Deliverables | Success Metrics |
|-------|--------|------------------|-----------------|
| **0 – Foundation** | 0‑3 | Core team, repo, CI, threat model, 10 design partners | Demo agent intercepts MCP calls with default‑deny + allow‑list |
| **1 – Wedge (pep‑mcp gateway)** | 3‑8 | MCP gateway, token service, decision log, consent UI, L0‑L3 ladder, 5 policy templates | p99 latency < 25 ms, 0 policy bypass in red‑team, 3 paying partners |
| **2 – Plan Compiler & Intent Binding** | 8‑13 | Plan compiler (intent → static plan), per‑step token service, plan‑level consent, agent‑framework adapters | ≥85 % plan success, ≤1.5 median consent clicks, zero cross‑plan token reuse |
| **3 – File System & Execution PEPs** | 13‑18 | `pep-fs` (LSFS) with rollback, `pep-exec` on Firecracker VMs, `pep-net` egress policy | 100% file rollback, sandbox escape tests pass, cold start < 500 ms |
| **4 – Causal Audit & Autopilot** | 18‑24 | eBPF causal labels, autopilot trust scoring, AuthZEN API, SPIFFE/ID‑JAG support | <8 % audit overhead, 100% incidents traceable to intent, enterprise contracts with audit/SIEM export |

### 3.3 Team Plan
| Phase | Headcount | Key Hires |
|------|-----------|--------------|
| P0 | 4 | Founders (systems, security) + 2 engineers |
| P1 | 7 | +MCP/protocol engineer, +design‑partner success |
| P2 | 11 | +2 (planner/LLM, frontend), first sales‑engineer |
| P3 | 15 | +2 (sandbox/Firecracker, FS engineer) |
| P4 | 20 | +eBPF engineer, +enterprise/field, +compliance lead |

## 4. Business Model
- **Open core**: gateway + plan compiler open source.
- **Enterprise**: RBAC/SCIM, IdP federation (Okta/Entra), SIEM export, audit viewer, VPC/on‑prem, rug‑pull detection, policy templates.
- **Pricing**: per authorization request (≈ $0.000025 per request, matching AWS AgentCore model) – aligns with runtime governance value.

## 4. Go‑to‑Market
1. **Wedge motion** – sell to AI‑platform teams already using MCP (the 12% that shipped). Message: “MCP has no permissions model; we are it.”
2. **Category motion** – “plan‑aware authorization” – contrast demos vs. per‑action confirmation (LSFS data shows plans scale better).
3. **Compliance motion** (P4) – AI Act & emerging agent‑audit requirements; sell to CISO, not just platform engineers.
5. **Community** – open‑source gateway, publish “Agent Supervision Benchmark” to own evaluation mindshare.

---

## 6. Risk Register (Key Risks & Mitigations)

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Incumbents add per‑step tokens | High | High | Speed plan‑compiler moat; open‑source wedge; standards seat (AuthZEN/MCP) |
| MCP spec adds native fine‑grained authz | Medium | Medium | Position above protocol: plans, consent UX, audit are protocol‑agnostic |
| Deputy/semantic authz unsolved → high‑profile incident | Medium | High | Never claim solved; L3 always‑human; publish research track; anomaly detection M4 |
| microVM cost at scale | Low | Medium | Managed E2B until 11K sandbox‑hrs/mo; self‑host path from day 1 |
| Gartner 40% cancellation wave | Medium | Medium | Counter‑cyclical pitch: we are the risk‑control fix |
| eBPF blocked in some kernels | Medium | Low | Userspace fallback (ptrace/LSM hooks); graceful degradation |

---

## 7. Success Metrics (North Star)

- **Primary**: Autonomous actions completed per human supervision‑hour.  
- **Supporting**: policy‑violation rate per 1K actions, median consents per task, % actions traceable to intent (target 100% by Phase 4), enterprise pilot→production conversion.

---

## 8. References (primary sources)

1. Mei et al., *AIOS*, COLM 2025 (arXiv:2403.16971)  
2. Shi et al., LSFS, ICLR 2025 (arXiv:2410.11843)  
3. Ge et al., LLM‑as‑OS vision (arXiv:2312.03815)  
4. Bao et al., AgentLoupe (arXiv:2610.23233)  
5. Leong, Trust Boundary (arXiv:2608.28502)  
6. OSWorld / OSWorld 2.0 leaderboards & adversarial study, 2026  
7. MCP 2026‑07‑28 revision & Enterprise Managed Authorization (Agentic AI Foundation / Linux Foundation)  
10. IDSync, *State of AI Agent Identity* 2026 (SPIFFE/WIMSE, AuthZEN, ID‑JAG consensus)  
16. Crunchbase AI‑governance funding data, Sep 2026 (435 M agent‑security rounds; Policy Enforcement 689 M)  
17. IDC/Lenovo (88% never ship); Gartner (40% cancellation prediction)  
18. E2B / microsandbox / Fly.io Sprites sandboxing analyses, 2026  
19. MCP gateway comparisons (Integrate.io, GetMaxim, Obot, Datawiza, agentgateway, Peta, etc.)  

---  

*End of specification*