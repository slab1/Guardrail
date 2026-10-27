# Guardrail OS — CI/CD Pipeline Overhaul & Native Rust PEP Integration

A comprehensive plan to resolve GitHub Actions CI/CD failures, establish full dual-engine testing (Python FastAPI + Native Rust PEP kernel), and integrate containerized multi-process execution with step summary reporting.

### User Review & Critical Decisions

> [!IMPORTANT]
> The following design decisions were confirmed during Phase 1 clarification:

- **Confirmed Decision 1 (CI Strategy)**: Full Dual-Engine validation running Python `pytest` security suites alongside Native Rust PEP compilation, unit tests, and performance benchmarks.
- **Confirmed Decision 2 (Daemon Integration)**: Multi-stage container entrypoint launching both the FastAPI application and the Native Rust PEP daemon concurrently.
- **Confirmed Decision 3 (Reporting)**: Automated GitHub Workflow Summary with a rich security audit status matrix and sub-10ms benchmark summary table generated on every push/PR.

---

### 1. Overview & Core Concept

- **What It Does**: Hardens the Guardrail OS CI/CD workflow (`.github/workflows/ci.yaml` and `.github/workflows/ci-cd.yml`), fixes secrets/environment injection (`GUARDRAIL_PEP_SECRET`), compiles and links the Native Rust PEP kernel daemon, and runs the dual-engine validation suite.
- **Target Audience**: Security Engineers, DevOps Engineers, and AI Safety Researchers auditing Guardrail OS kernel policy enforcement.
- **Key Value**: Guarantees cryptographically verified capability token validation and sub-10ms policy enforcement in both local containerized environments and GitHub Actions CI pipelines.

---

### 2. Pipeline Workflow & Summary UX

- **CI Step-by-Step Execution Flow**:
  1. **Lint & Syntax Matrix**: Validate Python ASGI endpoints and Rust PEP syntax with modern `dtolnay/rust-toolchain@stable`.
  2. **Rust PEP Kernel Build & Bench**: Compile `native_pep` binary in release mode and execute microbenchmarks.
  3. **Multi-Stage Container Spin-Up**: Launch Docker Compose with `GUARDRAIL_PEP_SECRET` configured, executing both `native_pep` daemon and FastAPI backend.
  4. **Data-Plane PEP Integration Tests**: Run `pytest tests/test_data_plane_pep.py -v` verifying token validation, nonce freshness, and authorization boundaries.
  5. **Security Summary Generation**: Render a structured Markdown report to `$GITHUB_STEP_SUMMARY` displaying test metrics, latency percentiles, and security checks.

---

### 3. Key Technical Decisions & Trade-Offs

- **Decision 1: Container Daemon Multi-Processing**
  - *Chosen Approach*: Lightweight entrypoint script (`entrypoint.sh`) in the final Docker image starting `native_pep` daemon in background on IPC socket/port before exec-ing `python3 app.py`.
  - *Why*: Ensures production containers and CI integration tests run against live active kernel enforcement rather than mock socket transports.
  - *Alternatives Considered*: Background sidecar runners in GitHub Actions (less representative of production container deployment).

- **Decision 2: Sub-10ms Benchmarking Tolerance**
  - *Chosen Approach*: Statistically sampled mean/p95 latency assertions in test runners with relaxed upper bounds for virtualized CI runner noise.
  - *Why*: Avoids intermittent CI pipeline flakiness caused by GitHub runner CPU throttling while strictly enforcing sub-10ms target performance on average.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        GitHub Actions Runner                           │
│                                                                        │
│   ┌─────────────────────┐               ┌──────────────────────────┐   │
│   │  Rust PEP Kernel    │               │  Python FastAPI Backend  │   │
│   │  (dtolnay/toolchain)│               │  (pytest & Zero-Trust)   │   │
│   └──────────┬──────────┘               └────────────┬─────────────┘   │
│              │                                       │                 │
│              └─────────────────┬─────────────────────┘                 │
│                                │                                       │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │   Docker Compose Engine Integration │                    │
│             │                                     │                    │
│             │   ┌──────────────┐ ┌──────────────┐ │                    │
│             │   │  FastAPI     │ │  Native PEP  │ │                    │
│             │   │  App (8000)  │ │ Daemon (8888)│ │                    │
│             │   └──────┬───────┘ └──────▲───────┘ │                    │
│             │          │  IPC / Secret  │         │                    │
│             │          └────────────────┘         │                    │
│             └──────────────────┬──────────────────┘                    │
│                                │                                       │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │     $GITHUB_STEP_SUMMARY Report     │                    │
│             └─────────────────────────────────────┘                    │
└────────────────────────────────────────────────────────────────────────┘
```

- **Container Environment File Mapping**:
  - `GUARDRAIL_PEP_SECRET`: Passed via GitHub repository secrets or fallback default in Docker Compose.
  - `PEP_DAEMON_PORT`: Configured to port `8888` for direct verification calls from FastAPI app.
- **Workflow Security Checklist**:
  - [x] Zero-trust OIDC token verification assertions
  - [x] Pending semantic guard approval checks
  - [x] Dual-engine benchmark validation table output
