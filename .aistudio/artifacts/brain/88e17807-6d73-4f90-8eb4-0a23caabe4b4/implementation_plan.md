# Implementation Plan — Two-Stage Release Workflow: Developer Preview to Production

Deliver a structured two-stage release workflow for Guardrail OS:
1. **Stage 1: Developer Preview Release**: Distribute Guardrail OS with complete source, installation guides, automated security test evidence (0 Bandit issues, 21/21 passed Pytest suite), and an interactive **Developer Review & Audit Portal**.
2. **Stage 2: Production Promotion Pipeline**: Provide a formal, verified gate-check workflow that transitions the kernel from Developer Preview to Production Release only after security review sign-off and multi-gate invariant verification.

---

## 1. Architecture & Workflow Design

```
+-----------------------------------------------------------------------------------------+
| STAGE 1: DEVELOPER PREVIEW RELEASE (v2.5.0-alpha)                                        |
| - Clear Security Boundary Advisory (Early release, not a certified production boundary) |
| - Full Source, Docker Compose & Standalone Setup Guides                                 |
| - Automated Verification Evidence: Bandit 0 issues, Pytest 21/21, Z3 SMT proofs         |
| - Interactive Developer Review Portal (Live benchmark, fault injection, checklist)     |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v [Developer / Security Review Sign-Off]
+-----------------------------------------------------------------------------------------+
| PRODUCTION RELEASE GATE VERIFICATION                                                    |
| [✓] Gate 1: Formal Developer Review Sign-Off recorded in tamper-evident ledger          |
| [✓] Gate 2: Automated Invariant Suite (Bandit AST 0 issues, 21/21 Pytest, Z3 SMT)       |
| [✓] Gate 3: Native PEP fail-closed enforcement (REQUIRE_NATIVE_PEP=1 & random key)       |
| [✓] Gate 4: Security Officer / Super Admin Authorization                                |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v [Promote to Production]
+-----------------------------------------------------------------------------------------+
| STAGE 2: PRODUCTION RELEASE (v2.5.0-GA)                                                 |
| - Kernel transitions to STRICT_PRODUCTION mode                                          |
| - Native Rust PEP required with hardware-adjacent token interception                     |
| - Tamper-evident cryptographic audit certificate generated and downloadable             |
+-----------------------------------------------------------------------------------------+
```

---

## 2. User Experience & UI Enhancements

- **Dedicated Two-Stage Release Portal** in the UI (accessible via the Header wordmark and the Governance tab):
  - **Stage 1 View (Developer Preview)**:
    - Quickstart installation cards (Docker Compose, Native Rust PEP, Python fastpath).
    - Live Test Runner widget: Runs or displays results for Bandit static security scan, Pytest suite, and Rust microsecond benchmark.
    - Interactive **Developer Review Form**: Auditors can test the kernel, verify invariants, add audit notes, and submit formal sign-off.
  - **Stage 2 View (Production Release Gate)**:
    - Live verification matrix showing status for each of the 4 production release gates.
    - "Promote to Production Release" action button (enabled once sign-off and all gates pass).
    - Production Status Dashboard: Displays Production Certificate, timestamp, verified invariants, and tamper-evident audit hash link.
    - One-click "Export Production Release Verification Bundle" (JSON/PDF-ready bundle).

---

## 3. Backend Kernel API Endpoints (`app.py`)

- `GET /api/release/status`:
  - Returns current release state (`DEVELOPER_PREVIEW` vs `PRODUCTION_RELEASE`), active version, gate checklist, developer reviews list, and promotion certificate (if promoted).
- `POST /api/release/review`:
  - Submits a developer review / security evaluation (reviewer name, role, organization, checklist items verified, review comments, decision: `APPROVED` | `NEEDS_REMEDIATION`).
  - Records the review to the tamper-evident SHA-256 audit ledger.
- `POST /api/release/promote`:
  - Verifies caller has role `super_admin`, `admin`, or `security_officer`.
  - Verifies that all 4 release gates are satisfied.
  - Transitions kernel release mode to `PRODUCTION_RELEASE`.
  - Appends a cryptographic promotion record to the audit ledger and saves state to `data/kernel_storage.json`.
- `POST /api/release/rollback`:
  - Allows reverting back to `DEVELOPER_PREVIEW` if new findings or regressions emerge during testing.

---

## 4. Verification & Testing Plan

1. **Automated Backend Tests (`tests/test_release_workflow.py`)**:
   - Test initial state defaults to `DEVELOPER_PREVIEW` with proper disclaimers.
   - Test developer review submission and audit ledger linkage.
   - Test that unapproved promotion attempts are rejected (400 Bad Request if gates are unmet).
   - Test successful promotion to `PRODUCTION_RELEASE` when all gates are satisfied.
2. **Security & Invariant Validation**:
   - Run `python -m bandit -r src/ -ll -ii` (must maintain 0 issues).
   - Run `python3 -m pytest tests/` (all tests passing).
   - Run `eslint` and `compile_applet` (0 errors).
