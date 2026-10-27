# Guardrail OS - Production Enforcement Gate Hardening Plan

1-2 sentence summary: Hardens Guardrail OS into a production-ready AI security gateway by enforcing native Rust PEP execution, Unix domain socket / HMAC-authenticated local IPC with peer verification, single-supervisor fail-fast startup, durable SQLite WAL revocation consistency, and zero-default secret enforcement.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural decisions have been confirmed in Phase 1 and govern this release hardening:

- **Confirmed Decision 1 (IPC Authentication)**: Unix domain socket at `/run/guardrail/pep.sock` with file permission restriction (`0600`) and socket peer credential validation, backed by HMAC-SHA256 authenticated message payloads (signed request ID, timestamp/nonce, protocol version `v2.5`).
- **Confirmed Decision 2 (Startup Supervision & Fail-Fast)**: Eliminate duplicate process launches. FastAPI kernel retries connection for up to 30 seconds with exponential backoff, verifies daemon protocol version and readiness, and immediately aborts startup (`exit 1`) if native PEP is unavailable or unauthenticated when required (`GUARDRAIL_USE_NATIVE_PEP=1` or `REQUIRE_NATIVE_PEP=1`).
- **Confirmed Decision 3 (Durable Revocation Coordination)**: Unified SQLite WAL database for revocations and consumed nonces. The Native Rust PEP queries or enforces the durable SQLite revocation store prior to capability execution, guaranteeing consistent token/plan revocation across restarts and workers.
- **Confirmed Decision 4 (Zero-Default Secret Policy)**: Remove `ci_docker_compose_secret_key_987654321` and all insecure fallback defaults from `docker-compose.yml`, `Dockerfile`, `app.py`, and `native_pep.rs`. Startup fails if `GUARDRAIL_PEP_SECRET` is missing or contains known test strings.

---

## 1. System Architecture & IPC Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                   FastAPI Control Plane (Port 8888)                    │
│  - Authoritative Firebase RS256 Auth & Tenant Isolation                │
│  - Z3 SMT Formal Verifier & Dual-LLM Heuristic Firewall                │
│  - Durable SQLite WAL Revocation & Nonce Store                         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                    Local Authenticated IPC
       (Unix Socket /run/guardrail/pep.sock / TCP 127.0.0.1:8889)
         - Peer Credential Validation (UID/GID)
         - HMAC-SHA256 Payload Signature
         - Max Message Size 64KB + Protocol Version v2.5
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Native Tier-2 Rust PEP Daemon (Fast-Path)                │
│  - Zero GC Constant-Time HMAC Signature Check                          │
│  - SQLite WAL Revocation & Nonce Linearity Enforcement                 │
│  - Canonical Resource Envelope Path Component Escapement Trap          │
│  - Active Linux Seccomp & eBPF Syscall Filter Telemetry Status         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Hardening Steps & Sub-System Strategy

### A. Environment & Process Supervision
- **Single Process Management**: Remove secondary `Popen` launch in FastAPI lifespan (`app.py`). Use container entrypoint (`docker-compose.yml` / `Dockerfile`) as single process supervisor.
- **Fail-Fast Startup Healthcheck**: In `app.py` lifespan, perform up to 30-second bounded exponential backoff retries to connect to `/run/guardrail/pep.sock` (or `127.0.0.1:8889`). Verify daemon ping response, protocol version `v2.5`, and secret handshake. Abort FastAPI startup (`sys.exit(1)`) if readiness check fails when native mode is required.
- **Eliminate Default Secrets**: Remove hardcoded default secrets from `docker-compose.yml` and `Dockerfile`. Update reject patterns in `native_pep.rs` and `data_plane_pep.py` to block `ci_docker_compose_secret_key_`.

### B. Authenticated Local IPC Protocol
- **IPC Transport**: Primary Unix domain socket `/run/guardrail/pep.sock` with fallback TCP `127.0.0.1:8889` for non-root local dev.
- **Authenticated Message Protocol**:
  ```json
  {
    "proto_ver": "v2.5",
    "request_id": "req_8f12a30b",
    "timestamp": 1729000000.123,
    "token_data": { ... },
    "requested_action": "file_read",
    "target_resource": "/workspace/config.json",
    "ipc_sig": "<hmac-sha256-of-payload-using-pep-secret>"
  }
  ```
- **Daemon Input Guards**: Enforce 64KB max buffer size, 1.0s socket timeout, malformed JSON rejection, and timestamp freshness check (±30s skew window).

### C. Unified Revocation & Anti-Replay Guarantees
- **Durable Revocation Checks in Native Rust**: Update `native_pep.rs` and `data_plane_pep.py` so that token/plan revocation sets are backed by `consumed_nonces.db` SQLite WAL table `revocations`.
- **Pre-Verification Revocation Gate**: Both Python and Rust PEP engines check SQLite revocation records prior to signature verification, ensuring immediate denial across process restarts and worker processes.

### D. Verification & Testing
- **End-to-End Integration Tests**: Update `tests/test_data_plane_pep.py` and add integration tests verifying:
  1. Daemon startup fail-fast when `REQUIRE_NATIVE_PEP=1` and daemon is down.
  2. Immediate rejection of forbidden default secrets.
  3. Consistent token & plan revocation denial across restarts.
  4. IPC HMAC signature verification and rejection of forged/tampered IPC messages.
- **Build & Lint Verification**: Run `compile_applet`, `lint_applet`, and `pytest tests/` to confirm zero regressions.
