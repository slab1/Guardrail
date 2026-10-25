"""Tests for Phase 3: PEP Framework, pep-fs, pep-exec, pep-net."""
import sys
import os
import tempfile

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from guardrail.pep_framework import (
    BasePEP, PEPRequest, PEPResponse, PEPType, PEPRegistry,
    get_pep_registry, register_pep, enforce_pep
)
from guardrail.pep_fs import PepFs, LSFSStore, create_pep_fs
from guardrail.pep_exec import PepExec, FirecrackerManager, MicroVMConfig, create_pep_exec
from guardrail.pep_net import PepNet, NetworkPolicyEngine, NetworkRule, NetworkAction, create_pep_net
from guardrail.token_service import create_step_token


# ----------------------------------------------------------------------
# PEP Framework Tests
# ----------------------------------------------------------------------
def test_pep_registry():
    """Test PEP registry."""
    registry = PEPRegistry()
    assert registry is not None
    assert len(registry.peps) == 0


def test_pep_registration():
    """Test PEP registration."""
    registry = PEPRegistry()
    
    class TestPEP(BasePEP):
        def __init__(self):
            super().__init__(PEPType.MCP)
            self.allowed_actions = {"test_action"}
        
        def enforce(self, request):
            return PEPResponse(success=True, result="test")
    
    test_pep = TestPEP()
    registry.register(test_pep)
    
    assert registry.get_pep(PEPType.MCP) == test_pep


def test_global_pep_registry():
    """Test global PEP registry."""
    registry1 = get_pep_registry()
    registry2 = get_pep_registry()
    assert registry1 is registry2


# ----------------------------------------------------------------------
# PEP-FS Tests
# ----------------------------------------------------------------------
def test_lsfs_store_creation():
    """Test LSFS store creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = LSFSStore(tmpdir)
        assert store.root_path.exists()


def test_lsfs_write_read():
    """Test LSFS write and read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = LSFSStore(tmpdir)
        
        # Write
        resp = store.write_file("/test/file.txt", b"Hello, World!")
        assert resp.success
        assert "version_id" in resp.result
        
        # Read
        resp = store.read_file("/test/file.txt")
        assert resp.success
        assert resp.result["content"] == b"Hello, World!"


def test_lsfs_delete():
    """Test LSFS delete."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = LSFSStore(tmpdir)
        
        # Write first
        store.write_file("/test/file.txt", b"Hello")
        
        # Delete
        resp = store.delete_file("/test/file.txt")
        assert resp.success
        assert resp.result["deleted"]


def test_lsfs_snapshot_rollback():
    """Test LSFS snapshot and rollback."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store = LSFSStore(tmpdir)
        
        # Write initial file
        store.write_file("/test/file.txt", b"Version 1")
        
        # Create snapshot
        snap_id = store.create_snapshot("initial")
        assert snap_id is not None
        
        # Modify file
        store.write_file("/test/file.txt", b"Version 2")
        
        # Rollback
        resp = store.rollback_to_snapshot(snap_id)
        assert resp.success
        
        # Verify rollback
        resp = store.read_file("/test/file.txt")
        assert resp.success
        assert resp.result["content"] == b"Version 1"


def test_pep_fs_enforce():
    """Test PepFs enforcement."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pep_fs = PepFs(LSFSStore(tmpdir))
        
        token = create_step_token("plan_001", "step_001", "Write file", "coding", "user1", 1)
        
        request = PEPRequest(
            pep_type=PEPType.FS,
            token=token,
            plan_id="plan_001",
            step_id="step_001",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
            action="file_write",
            resource="/test/file.txt",
            metadata={"content": "Test content"}
        )
        
        response = pep_fs.enforce(request)
        assert response.success
        assert "version_id" in response.result
        assert response.rollback_info is not None


def test_pep_fs_invalid_token():
    """Test PepFs with invalid token."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pep_fs = PepFs(LSFSStore(tmpdir))
        
        request = PEPRequest(
            pep_type=PEPType.FS,
            token="invalid_token",
            plan_id="plan_001",
            step_id="step_001",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
            action="file_read",
            resource="/test/file.txt",
            metadata={}
        )
        
        response = pep_fs.enforce(request)
        assert not response.success
        assert "Invalid or expired token" in response.error


# ----------------------------------------------------------------------
# PEP-Exec Tests (Mock)
# ----------------------------------------------------------------------
def test_firecracker_manager_creation():
    """Test FirecrackerManager creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = FirecrackerManager(tmpdir)
        assert manager.base_path == tmpdir


def test_microvm_config():
    """Test MicroVMConfig creation."""
    config = MicroVMConfig(vm_id="test-vm-001", cpu_count=2, memory_mib=256)
    assert config.vm_id == "test-vm-001"
    assert config.cpu_count == 2
    assert config.memory_mib == 256


def test_pep_exec_creation():
    """Test PepExec creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pep_exec = PepExec(FirecrackerManager(tmpdir))
        assert pep_exec.pep_type == PEPType.EXEC
        assert "shell_command" in pep_exec.allowed_actions


# ----------------------------------------------------------------------
# PEP-Net Tests
# ----------------------------------------------------------------------
def test_network_policy_engine():
    """Test NetworkPolicyEngine."""
    engine = NetworkPolicyEngine()
    assert engine.default_deny is True
    assert len(engine.rules) == 0


def test_network_rule_creation():
    """Test NetworkRule creation."""
    rule = NetworkRule(
        name="test_rule",
        action=NetworkAction.HTTP_GET,
        allowed_domains=["example.com"],
        allowed_ports=[443],
    )
    assert rule.name == "test_rule"
    assert rule.action == NetworkAction.HTTP_GET


def test_network_policy_evaluation():
    """Test network policy evaluation."""
    engine = NetworkPolicyEngine()
    
    # Add rule allowing HTTPS to example.com
    engine.add_rule(NetworkRule(
        name="allow_example_https",
        action=NetworkAction.HTTP_GET,
        allowed_domains=["example.com"],
        allowed_ports=[443],
        allowed_protocols=["https"],
    ))
    
    from pep_net import NetworkRequest
    
    # Allowed request
    req = NetworkRequest(
        action=NetworkAction.HTTP_GET,
        url="https://example.com/api",
        host="example.com",
        port=443,
    )
    allowed, rule_name, reason = engine.evaluate(req)
    assert allowed
    assert rule_name == "allow_example_https"
    
    # Denied request (HTTP not HTTPS)
    req2 = NetworkRequest(
        action=NetworkAction.HTTP_GET,
        url="http://example.com/api",
        host="example.com",
        port=80,
    )
    allowed2, _, _ = engine.evaluate(req2)
    assert not allowed2


def test_pep_net_enforce():
    """Test PepNet enforcement."""
    pep_net = PepNet()
    
    token = create_step_token("plan_001", "step_001", "HTTP GET", "coding", "user1", 1)
    
    request = PEPRequest(
        pep_type=PEPType.NET,
        token=token,
        plan_id="plan_001",
        step_id="step_001",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
        action="http_get",
        resource="https://api.github.com/users/octocat",
        metadata={
            "url": "https://api.github.com/users/octocat",
            "host": "api.github.com",
            "port": 443,
            "method": "GET",
        }
    )
    
    # This will try to make actual network request - mock it for testing
    # We'll just test the policy evaluation part
    from pep_net import NetworkRequest
    net_request = NetworkRequest(
        action=NetworkAction.HTTP_GET,
        url="https://api.github.com/users/octocat",
        host="api.github.com",
        port=443,
    )
    
    allowed, rule_name, reason = pep_net.policy_engine.evaluate(net_request)
    assert allowed
    assert rule_name == "allow_https_apis"


def test_pep_net_deny_non_tls():
    """Test PepNet denies non-TLS requests."""
    pep_net = PepNet()
    
    from pep_net import NetworkRequest
    net_request = NetworkRequest(
        action=NetworkAction.HTTP_GET,
        url="http://example.com",
        host="example.com",
        port=80,
    )
    
    allowed, rule_name, reason = pep_net.policy_engine.evaluate(net_request)
    assert not allowed


def test_pep_registry_integration():
    """Test full PEP registry integration."""
    # Create and register all PEPs
    pep_fs = create_pep_fs()
    pep_exec = create_pep_exec()
    pep_net = create_pep_net()
    
    registry = get_pep_registry()
    
    assert registry.get_pep(PEPType.FS) is pep_fs
    assert registry.get_pep(PEPType.EXEC) is pep_exec
    assert registry.get_pep(PEPType.NET) is pep_net


# ----------------------------------------------------------------------
# Run tests
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])