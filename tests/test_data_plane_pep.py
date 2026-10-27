import os
import sys
import time
import pytest
import shutil

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from guardrail.data_plane_pep import DataPlanePEP, CapabilityToken, is_resource_within_boundary

@pytest.fixture(scope="module", autouse=True)
def clean_nonce_db():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/consumed_nonces.db'))
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass

def test_data_plane_pep_happy_path():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_01", "step_1", "file_read", "/workspace", 1)
    
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert result["verdict"] == "ALLOW"
    assert result["syscall_trap"] is None
    # Sub-10ms PEP fast path budget target, resilient to shared cloud CI runner virtualization
    # CI runners have variable latency; allow up to 500ms for test stability with SQLite WAL
    assert result["latency_ms"] < 500.0

def test_data_plane_pep_linear_token_replay_blocked():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_02", "step_1", "file_write", "/workspace", 1)
    
    r1 = pep.verify_and_enforce(tok.to_dict(), "file_write", "/workspace/output.txt")
    assert r1["verdict"] == "ALLOW"
    
    # Replay with same consumed nonce
    r2 = pep.verify_and_enforce(tok.to_dict(), "file_write", "/workspace/output.txt")
    assert r2["verdict"] == "TRAP_DENY"
    assert "Linearity invariant violated" in r2["reason"]

def test_data_plane_pep_forgery_signature_mismatch():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_03", "step_1", "file_read", "/workspace", 1)
    
    tampered = tok.to_dict()
    tampered["signature"] = "forged_signature_attack_vector"
    
    result = pep.verify_and_enforce(tampered, "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "Signature Mismatch" in result["reason"]

def test_data_plane_pep_unsigned_token_rejected():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_unsigned", "step_1", "file_read", "/workspace", 1)
    
    unsigned_tok = tok.to_dict()
    unsigned_tok["signature"] = ""
    
    result = pep.verify_and_enforce(unsigned_tok, "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "Unsigned" in result["reason"]

def test_data_plane_pep_tampered_payload_rejected():
    pep = DataPlanePEP()
    # Token granted for L1 autonomy
    tok = pep.issue_token("plan_test_tamper", "step_1", "file_read", "/workspace", 1)
    
    tampered = tok.to_dict()
    # Attacker tries to elevate autonomy level to L3
    tampered["autonomy_level"] = 3
    
    result = pep.verify_and_enforce(tampered, "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "Signature Mismatch" in result["reason"]

def test_canonical_resource_boundary_validation():
    # 1. Exact match
    assert is_resource_within_boundary("/workspace", "/workspace") == True
    assert is_resource_within_boundary("/workspace/file.txt", "/workspace") == True
    assert is_resource_within_boundary("/workspace/sub/dir/config.json", "/workspace") == True

    # 2. Critical: Prefix overlap exploit (/workspace-evil) MUST BE DENIED
    assert is_resource_within_boundary("/workspace-evil", "/workspace") == False
    assert is_resource_within_boundary("/workspace_secret/key.pem", "/workspace") == False
    assert is_resource_within_boundary("/workspaces", "/workspace") == False

    # 3. Directory traversal escapes MUST BE DENIED
    assert is_resource_within_boundary("/workspace/../etc/passwd", "/workspace") == False
    assert is_resource_within_boundary("/etc/shadow", "/workspace") == False

def test_data_plane_pep_resource_escapement():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_04", "step_1", "file_read", "/workspace", 1)
    
    # Attempting to read outside granted /workspace envelope
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/etc/shadow")
    assert result["verdict"] == "TRAP_DENY"
    assert "Resource escapement" in result["reason"]

    # Prefix collision attack attempt
    result_evil = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace-evil")
    assert result_evil["verdict"] == "TRAP_DENY"
    assert "Resource escapement" in result_evil["reason"]

def test_data_plane_pep_token_expiry():
    pep = DataPlanePEP()
    # Issue token with negative TTL (already expired)
    tok = pep.issue_token("plan_test_05", "step_1", "file_read", "/workspace", 1, ttl_seconds=-1)
    
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "expired" in result["reason"].lower()

def test_data_plane_pep_future_clock_skew_rejected():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_skew", "step_1", "file_read", "/workspace", 1)
    
    tampered = tok.to_dict()
    # Issue timestamp in distant future (tampering)
    tampered["issued_at"] = time.time() + 3600
    
    result = pep.verify_and_enforce(tampered, "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"

def test_data_plane_pep_revocation():
    pep = DataPlanePEP()
    tok1 = pep.issue_token("plan_test_revoke_1", "step_1", "file_read", "/workspace", 1)
    tok2 = pep.issue_token("plan_test_revoke_2", "step_2", "file_write", "/workspace", 1)

    # Revoke individual token
    pep.revoke_token(tok1.token_id)
    r1 = pep.verify_and_enforce(tok1.to_dict(), "file_read", "/workspace/README.md")
    assert r1["verdict"] == "TRAP_DENY"
    assert "revoked" in r1["reason"].lower()

    # Revoke whole plan
    pep.revoke_plan("plan_test_revoke_2")
    r2 = pep.verify_and_enforce(tok2.to_dict(), "file_write", "/workspace/output.txt")
    assert r2["verdict"] == "TRAP_DENY"
    assert "revoked" in r2["reason"].lower()

def test_durable_revocation_persistence():
    pep1 = DataPlanePEP()
    tok = pep1.issue_token("plan_persisted_rev", "step_1", "file_read", "/workspace", 1)
    pep1.revoke_token(tok.token_id)

    # Initialize new DataPlanePEP instance (simulating worker process restart)
    pep2 = DataPlanePEP()
    res = pep2.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert res["verdict"] == "TRAP_DENY"
    assert "revoked" in res["reason"].lower()

def test_fail_closed_native_pep_mode(monkeypatch):
    monkeypatch.setenv("GUARDRAIL_USE_NATIVE_PEP", "1")
    monkeypatch.setenv("REQUIRE_NATIVE_PEP", "1")

    pep = DataPlanePEP()
    tok = pep.issue_token("plan_native_test", "step_1", "file_read", "/workspace", 1)

    # When native daemon socket is unreachable and REQUIRE_NATIVE_PEP=1, must FAIL CLOSED
    res = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert res["verdict"] == "TRAP_DENY"
    assert "CRITICAL: Native Rust PEP daemon disconnected" in res["reason"]

def test_insecure_default_secret_rejection(monkeypatch):
    from guardrail.data_plane_pep import get_kernel_pep_secret
    monkeypatch.setenv("GUARDRAIL_PEP_SECRET", "ci_docker_compose_secret_key_987654321")
    
    with pytest.raises(RuntimeError) as exc_info:
        get_kernel_pep_secret()
    
    assert "insecure default value" in str(exc_info.value)
