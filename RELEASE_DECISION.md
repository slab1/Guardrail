# Guardrail OS — Release Decision & Security Evaluation

**Release Classification**: **Public Alpha / Developer Preview (v2.5.0-alpha)**  
**Audit Evaluation Date**: October 2026  
**System**: Guardrail OS Dual-Tier Agent Safety Kernel  

---

## 1. Release Classification & Decision

### 1.1 Public Alpha / Developer Preview — **APPROVED**
Guardrail OS is published as an early **Public Alpha / Developer Preview** for evaluation, testing, academic research, and prototype integration with autonomous AI agent workflows.

> **CRITICAL SECURITY DISCLAIMER**  
> Guardrail OS v2.5.0-alpha is an early research and developer release. It is **NOT** a certified production security boundary or EAL/FIPS-validated reference monitor. It must not be deployed as the sole isolation layer in hostile multi-tenant environments without virtualization-based sandboxing (e.g., Firecracker MicroVMs, gVisor, or kata-containers).

### 1.2 Production Security Release — **HELD (PENDING VERIFICATION GATES)**
A certified production security release remains **gated**. As documented in the independent security review, full production certification requires further verification of:
1. End-to-end host OS-level syscall blocking (`SIGSYS`/seccomp) across production kernels rather than hardware-adjacent fast-path token gates alone.
2. Production deployment orchestration behavior under catastrophic daemon failure and network partition.
3. Distributed multi-node consensus for revocation and replay guarantees across cloud clusters (beyond single-node SQLite WAL).

---

## 2. Installation & Quickstart Instructions

### Method A: Hardened Docker Compose (Recommended)
This topology launches the compiled Native Rust PEP daemon with Unix domain socket credentials (`/run/guardrail/pep.sock`), shared SQLite WAL volume, and the Python FastAPI kernel:

```bash
# 1. Generate a high-entropy 256-bit cryptographic key
export GUARDRAIL_PEP_SECRET=$(openssl rand -hex 32)

# 2. Build and launch with Native Rust PEP enforced
GUARDRAIL_PEP_SECRET=$GUARDRAIL_PEP_SECRET docker compose up --build -d

# 3. Check container and kernel health probe
curl -s http://localhost:8888/api/kernel/state | jq
curl -s http://localhost:8888/api/pep/health | jq
```

### Method B: Standalone Developer Installation

```bash
# 1. Clone repository
git clone https://github.com/slab1/Guardrail.git && cd Guardrail

# 2. Install Node/Bun dependencies for UI
npm install

# 3. Install Python kernel dependencies
python3 -m pip install -r requirements.txt uvicorn pytest bandit

# 4. (Optional) Build Native Rust PEP Daemon
cargo build --release
GUARDRAIL_PEP_SECRET=$(openssl rand -hex 32) target/release/guardrail-pep-daemon &

# 5. Launch Full-Stack Development Server
npm run dev
```
- **Web UI**: `http://localhost:3000`
- **FastAPI Kernel API**: `http://localhost:8888`
- **API Documentation**: `http://localhost:8888/docs`

---

## 3. Known Limitations & Production Gating Items

| Gate / Requirement | Current Implementation Status | Limitation & Production Gap |
| :--- | :--- | :--- |
| **OS-Level Syscall Blocking** | Hardware-adjacent fast-path token validation (<0.02ms) with Seccomp BPF profile synthesis and `SIGSYS (31)` simulation. | Direct Linux kernel BPF attach requires `CAP_SYS_ADMIN` and host kernel `CONFIG_SECCOMP`. Unprivileged containers and non-Linux hosts run under hardware-adjacent token emulation rather than raw kernel traps. |
| **Daemon Failure Resiliency** | 30-second bounded exponential backoff readiness handshake with fail-closed termination (`sys.exit(1)` under `REQUIRE_NATIVE_PEP=1`). | Requires external process supervision (systemd or Kubernetes restart policies). Daemon crashes during active transactions require idempotency handling on agent actuator calls. |
| **Cross-Engine Revocation & Replay** | Synchronized authoritative SQLite WAL tables (`consumed_nonces` and `revocations`) queried directly by both Python and Rust engines. | Guaranteed on single host/node via POSIX file locks and WAL journaling. Multi-node cloud deployments require shared replicated storage or distributed consensus (e.g. Raft/Redis). |
| **Cryptographic Secrets** | Rejection of known insecure strings (`default_secret_*`, `ci_docker_compose_secret_key_*`, `changeme*`). | Secrets must be injected via external key vaults (GCP Secret Manager, AWS KMS, or HashiCorp Vault) rather than static files. |

---

## 4. Security-Testing & Invariant Verification Evidence

The codebase has undergone comprehensive automated invariant and vulnerability verification:

### 4.1 Bandit AST Static Security Analysis
- Command: `python -m bandit -r src/ -ll -ii`
- **Result: 0 Medium / 0 High Vulnerabilities Identified (PASS)**
- All socket path resolutions utilize dedicated `/run/guardrail/pep.sock` runtime directories with secure `tempfile.gettempdir()` fallbacks (CWE-377 / B108 resolved).

### 4.2 Pytest Invariant Suite (27/27 Tests Passed)
- **Signature Forgery Resistance**: `test_data_plane_pep_forgery_signature_mismatch` ensures any altered bit in capability tokens triggers instant `TRAP_DENY`.
- **Linear Replay Prevention**: `test_data_plane_pep_linear_token_replay_blocked` validates atomic single-use nonce consumption backed by ACID SQLite WAL transaction locks.
- **Fail-Closed Revocation & Nonce Failure**: `test_revocation_store_fail_closed` and `test_authoritative_revocation_direct_sqlite` guarantee that database failures fail closed and external SQLite revocations immediately invalidate tokens across engines.
- **Bilateral Authenticated IPC**: `test_authenticated_ipc_handshake_and_tamper_defense` proves HMAC challenge-response verification blocks unauthorized socket peers.
- **Component-Aware Path Boundary Validation**: `test_canonical_resource_boundary_validation` and Rust `test_path_traversal_prevention` prove directory traversal (`/workspace/../etc/passwd`), symlink escapes, and prefix escapes (`/workspace-evil`) are strictly rejected.
- **Evidence-Bound Release Promotion Workflow**: `test_release_workflow.py` proves that production promotion requires Security Officer Sign-Off bound to the exact build artifact digest (SHA-256), dynamic Bandit static scan, dynamic invariant suite execution, and live Native PEP enforcement, with zero casual override bypasses.
- **Role-Based Audit Enforcement**: `test_operator_cannot_review_or_promote` confirms unprivileged roles (`operator`) cannot submit sign-offs or promote releases.

### 4.3 Native Rust PEP Self-Tests
- Command: `PEP_SELF_TEST_ONLY=1 cargo test --release`
- Verified sub-microsecond enforcement (<0.01ms), constant-time HMAC comparison, SQLite WAL constraint validation, and component-aware canonical path boundary enforcement.

---

## 5. Summary of Security Remediation Actions

| Issue Area | Remediation Applied |
| :--- | :--- |
| **Path Traversal Escape** | Implemented component-aware canonical path validation (`normalize_path_components` + `canonicalize` + `Path::starts_with`) in both Rust (`native_pep.rs`) and Python (`data_plane_pep.py`). Traversal attacks like `/workspace/../etc/passwd` and sibling escapes like `/workspace-evil` are strictly blocked. |
| **Fail-Closed Store Outages** | `DurableNonceStore` now raises `RuntimeError` on database errors during init or nonce consumption, and `verify_and_enforce()` catches store exceptions to return `TRAP_DENY`. Database outages cannot yield `ALLOW` decisions. |
| **Release Gate Security** | Replaced hardcoded status gates with dynamic evidence verification. `POST /api/release/review` strictly requires `security_officer` or `super_admin` role and binds sign-offs to the SHA-256 `artifact_digest`. |
| **Promotion Override Removal** | Removed `override_warning` bypass from normal promotion logic. `POST /api/release/promote` independently evaluates all 4 mandatory gates dynamically before issuing a promotion certificate. |


## 5. Contact & Vulnerability Reporting

To report security vulnerabilities or contribute to Guardrail OS formal safety proofs, please submit an issue or contact the maintainers at `slablaykon@gmail.com`.
