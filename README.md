# Guardrail Project

**Intelligent OS Policy Engine (Guardrail)**  
A non‑bypassable policy engine that sits between LLM agents and every actuator (files, shell, network, MCP tools).  
It enforces intent‑bound, per‑step, short‑lived capabilities on a graduated‑autonomy consent ladder with kernel‑level causal audit.

## Project Structure
```
/guardrail-project
├── src/                # Python source code
│   └── plan_compiler/    # (example) intent → plan compiler
├── tests/              # unit / integration tests
├── .github/
│   └── workflows/      # GitHub Actions CI/CD
├── .gitignore
├── README.md
└── README_spec.md      # detailed spec (this file)
```

## 1. Overview
- **Goal**: Build an intelligent operating system where AI agents can act safely and autonomously.
- **Core idea**: A policy engine that grants intent‑bound, per‑step, short‑lived capabilities, with graduated autonomy and causal audit.

## 2. Phased Roadmap
| Phase | Timeframe | Goal |
|-------|-----------|------|
| **0 – Foundation** | 0‑3 months | Repo, team, CI, threat model, demo MCP intercept |
| **1 – Wedge (pep‑mcp gateway)** | 3‑8 months | MCP gateway with fine‑grained intent‑scoped permissions, consent UI, L0‑L3 ladder, policy templates |
| **2 – Plan Compiler & Intent Binding** | 8‑13 months | LLM planner → structured plan → per‑step token service; plan‑level consent |
| **3 – File System & Execution PEPs** | 13‑18 months | `pep-fs` (LSFS), `pep-exec` on Firecracker microVMs, `pep-net` |
| **4 – Causal Audit & Autopilot** | 18‑24 months | eBPF causal audit, autopilot trust scoring, AuthZEN integration, production‑grade audit/SIEM export |

## 3. Team & Roles
- **Systems Lead** – architecture, containerization, sandboxing
- **Policy/Security Engineer** – PDP, token service, audit, biometric auth design
- **Product Engineer** – UI/UX, workflow design, user stories
- **LLM Engineer** – model integration, plan compiler, token service

## 4. Success Metrics (North Star)
- **Primary**: Autonomous actions completed per human supervision‑hour.
- **Secondary**: Policy‑violation rate per 1K actions, median consents per task, % actions traceable to intent (target 100% by Phase 4), pilot‑to‑production conversion.

## 6. References
- Mei et al., *AIOS*, COLM 2025  
- Shi et al., LSFS, ICLR 2025  
- Ge et al., LLM‑as‑OS vision (arXiv 2023)  
- Bao et al., AgentLoupe (arXiv 2026)  
- Leong, Trust Boundary (arXiv 2026)  
- MCP 2026‑07‑28 spec, OpenROUTER API docs  
- IDC/Lenovo, Gartner reports on agent adoption  

*End of README.*