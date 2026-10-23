# Guardrail Project Plan

## Overview
Guardrail is the authorization and safety layer for an intelligent operating system. It provides:
- Non-bypassable policy enforcement between LLM agents and actuators (files, shell, network, MCP tools)
- Intent-bound, per-step, short-lived capabilities (instead of session-level permissions)
- Graduated autonomy on a consent ladder
- Causal audit via kernel-level eBPF tracing

## Project Phases

### Phase 0: Foundation (Months 0-3)
- Set up repository, team, CI/CD, threat model
- Fork/deploy MCP SDK, Cedar, LSFS reference code
- CI pipeline, threat model documentation
- 10 design partner conversations (AI platform teams + consultancies)
- Exit criteria: Guardrail intercepts MCP tool calls with default-deny + allow-list policy in a demo agent

### Phase 1: Wedge - pep-mcp Gateway (Months 3-8)
- MCP client-side gateway with token minting and decision logging
- Consent UI for plan diffs and autonomy ladder
- L0-L3 autonomy ladder for MCP tool classes
- Policy templates for 5 reference agent classes (coding, data-analysis, travel/booking, email/comms, file-organizer)
- Metrics: p99 added latency < 25ms, 0 policy bypass in red-team suite, 3 paying design partners

### Phase 2: Plan Compiler + Intent Binding (Months 8-13)
- LLM planner → structured plan → static validation (resource globs, action enum, reversibility)
- Per-step token service; intent field signed into token; plan-level consent (approve once per plan, tokens per step)
- Integration with LangGraph & OpenAI Agents SDK + ReAct adapter
- Metrics: plan-execution success ≥ 85% on 100-task harness; consent clicks ≤ 1.5 median; zero cross-plan token reuse

### Phase 3: File System & Execution PEPs (Months 13-18)
- `pep-fs` over LSFS: semantic resources, L1 auto-allow, time/version rollback
- `pep-exec` on Firecracker microVMs: hardware-isolated execution, PEP as only egress
- `pep-net`: domain/port/payload-class egress policy; secrets injected at proxy
- Metrics: 100% file rollback, sandbox escape tests pass, cold start < 500ms

### Phase 4: Causal Audit + Autopilot (Months 18-24)
- eBPF causal labels (AgentLoupe-style) for host-level attribution
- Autopilot trust scoring: closed loop from violation-free history → autonomy elevation
- AuthZEN-compatible decision API, SPIFFE workload identities, ID-JAG enterprise brokering
- Metrics: <8% audit overhead, 100% flagged incidents traceable to intent, first enterprise contracts with audit/SIEM export

### Phase 5: Production & Scale (Months 24+)
- Full production deployment, scaling, monitoring, and continuous improvement

## Team Plan

| Phase | Headcount | Key Hires |
|-------|-----------|-----------|
| P0 | 4 | Founders (systems, security), 2 engineers |
| P1 | 7 | +MCP/protocol engineer, +design partner success |
| P3 | 11 | +2 (planner/LLM, frontend), first sales-engineer |
| P3 | 15 | +2 (sandbox/Firecracker, FS engineer) |
| P4 | 20 | +eBPF engineer, +enterprise/field, +compliance lead |

## Business Model
- Open core: gateway + plan compiler open source
- Enterprise: RBAC/SCIM, IdP federation, SIEM export, audit viewer, VPC/on-prem, rug-pull detection, policy templates
- Pricing: per authorization-request (e.g., $0.000025/req) – aligns with runtime governance value

## Go-To-Market
1. Wedge motion (P1) – target AI-platform teams deploying MCP agents (the 12% that shipped)
2. Category motion (P2-P3) – "plan-aware authorization" vs per-action confirmation
3. Compliance motion (P4) – AI Act & agent-audit requirements; sell to CISO
4. Community – open-source gateway + Agent Supervision Benchmark

---

## 6. Risk Register (Key Risks & Mitigations)

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Incumbents add per-step tokens | High | High | Speed plan-compiler moat; open-source wedge; standards seat |
| MCP spec adds native fine-grained authz | Medium | Medium | Position above protocol; plans, consent UX, audit are protocol-agnostic |
| Deputy/semantic authz unsolved → incident | Medium | High | Never claim solved; L3 always-human; publish research track; anomaly detection M4 |
| microVM cost at scale | Low | Medium | Managed E2B until 11K sandbox-hrs/mo; self-host path from day 1 |
| Gartner 40% cancellation wave | Medium | Medium | Counter-cyclical pitch: we provide missing risk controls |
| eBPF blocked in kernels | Medium | Low | Userspace fallback (ptrace/LSM hooks); degrade gracefully |

---

## 6. Success Metrics (North Star)

- **Primary**: Autonomous actions completed per human supervision-hour
- **Supporting**: policy-violation rate per 1K actions, median consents per task, % actions traceable to intent (target 100% by Phase 4), enterprise pilot→production conversion

---

## 8. References (Primary Sources)

1. Mei et al., AIOS, COLM 2025 (arXiv:2403.16971)  
2. Shi et al., LSFS, ICLR 2025 (arXiv:2410.11843)  
3. Ge et al., LLM-as-OS vision (arXiv:2312.03815)  
4. Bao et al., AgentLoupe (arXiv:2610.23233)  
5. Leong, Trust Boundary (arXiv:2608.28502)  
6. OSWorld / OSWorld 2.0 leaderboards & adversarial study, 2026  
7. MCP 2026-07-28 revision & Enterprise Managed Authorization (Agentic AI Foundation / Linux Foundation)  
10. IDSync, State of AI Agent Identity 2026 (SPIFFE/WIMSE, AuthZEN, ID-JAG)  
13. Crunchbase AI-governance funding data, Sep 2026  
14. IDC/Lenovo (88% never ship); Gartner (40% cancellation prediction)  
15. E2B / microsandbox / Fly.io Sprites sandboxing analyses, 2026  
16. MCP gateway comparisons (Integrate.io, Obot, Lunar.dev, Kong, etc.)  

---

*End of document*