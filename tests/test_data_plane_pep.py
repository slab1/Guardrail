import pytest
import time
from guardrail.data_plane_pep import DataPlanePEP, CapabilityToken

def test_data_plane_pep_happy_path():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_01", "step_1", "file_read", "/workspace/", 1)
    
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert result["verdict"] == "ALLOW"
    assert result["syscall_trap"] is None
    assert result["latency_ms"] < 1.0  # Must be sub-millisecond

def test_data_plane_pep_linear_token_replay_blocked():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_02", "step_1", "file_write", "/workspace/", 1)
    
    r1 = pep.verify_and_enforce(tok.to_dict(), "file_write", "/workspace/output.txt")
    assert r1["verdict"] == "ALLOW"
    
    # Replay with same consumed nonce
    r2 = pep.verify_and_enforce(tok.to_dict(), "file_write", "/workspace/output.txt")
    assert r2["verdict"] == "TRAP_DENY"
    assert "Linearity invariant violated" in r2["reason"]

def test_data_plane_pep_forgery_signature_mismatch():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_03", "step_1", "file_read", "/workspace/", 1)
    
    tampered = tok.to_dict()
    tampered["signature"] = "forged_signature_attack_vector"
    
    result = pep.verify_and_enforce(tampered, "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "Signature Mismatch" in result["reason"]

def test_data_plane_pep_resource_escapement():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_04", "step_1", "file_read", "/workspace/", 1)
    
    # Attempting to read outside granted /workspace/ envelope
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/etc/shadow")
    assert result["verdict"] == "TRAP_DENY"
    assert "Resource escapement" in result["reason"]

def test_data_plane_pep_token_expiry():
    pep = DataPlanePEP()
    # Issue token with negative TTL (already expired)
    tok = pep.issue_token("plan_test_05", "step_1", "file_read", "/workspace/", 1, ttl_seconds=-1)
    
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert result["verdict"] == "TRAP_DENY"
    assert "expired" in result["reason"].lower()
