import os
import sys
import time
import pytest

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from guardrail.data_plane_pep import DataPlanePEP, CapabilityToken, is_resource_within_boundary

def test_data_plane_pep_happy_path():
    pep = DataPlanePEP()
    tok = pep.issue_token("plan_test_01", "step_1", "file_read", "/workspace", 1)
    
    result = pep.verify_and_enforce(tok.to_dict(), "file_read", "/workspace/README.md")
    assert result["verdict"] == "ALLOW"
    assert result["syscall_trap"] is None
    assert result["latency_ms"] < 2.0  # Must be sub-millisecond to low millisecond fast path

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
