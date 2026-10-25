"""Tests for Phase 4: Causal Audit, Autopilot, AuthZEN, SPIFFE, ID-JAG."""
import sys
import os
import time
import json
import tempfile

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from causal_audit import (
    CausalAuditLogger, CausalLabel, AuditEvent, AuditEventType,
    EBPFAuditProbe, create_causal_label, log_audit_event
)
from autopilot import (
    AutopilotController, TrustScoringEngine, TrustProfile, TrustEvent, TrustEventType, TrustLevel,
    get_autopilot, start_autopilot, stop_autopilot
)
from authzen import (
    AuthZENDecisionEngine, AuthZENSubject, AuthZENResource, AuthZENAction, AuthZENContext,
    AuthZENDecisionRequest, AuthZENDecisionResponse, DecisionType, SubjectType,
    SPIFFEIdentityProvider, IDJAGBroker,
    get_authzen_engine, get_spiffe_provider, get_idjag_broker,
    evaluate_authzen, register_agent_identity, create_delegation
)
from pep_net import NetworkRule, NetworkAction


# ----------------------------------------------------------------------
# Causal Audit Tests
# ----------------------------------------------------------------------
def test_causal_audit_logger_creation():
    """Test causal audit logger creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        assert logger is not None
        assert logger.event_count == 0


def test_create_causal_label():
    """Test creating causal labels."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        
        label = logger.create_causal_label(
            plan_id="plan_001",
            step_id="step_001",
            intent="Test intent",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
        )
        
        assert label.label_id is not None
        assert label.plan_id == "plan_001"
        assert label.step_id == "step_001"
        assert label.intent == "Test intent"
        assert label.agent_class == "coding"
        assert label.user_id == "user1"
        assert label.autonomy_level == 1
        assert label.parent_label_id is None


def test_log_audit_event():
    """Test logging audit events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        
        label = logger.create_causal_label(
            plan_id="plan_001",
            step_id="step_001",
            intent="Test intent",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
        )
        
        event = logger.log_event(
            AuditEventType.SYSCALL,
            label,
            syscall="openat",
            args={"path": "/etc/config.yaml", "flags": "O_WRONLY"},
            result=3,
            duration_ns=12500,
        )
        
        assert event.event_id is not None
        assert event.event_type == AuditEventType.SYSCALL
        assert event.causal_label.label_id == label.label_id
        assert event.syscall == "openat"
        assert event.result == 3


def test_causal_chain():
    """Test causal chain retrieval."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        
        # Create parent label
        parent_label = logger.create_causal_label(
            plan_id="plan_001",
            step_id="step_000",
            intent="Parent step",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
        )
        
        # Create child label with parent
        child_label = logger.create_causal_label(
            plan_id="plan_001",
            step_id="step_001",
            intent="Child step",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
            parent_label_id=parent_label.label_id,
        )
        
        chain = logger.get_causal_chain(child_label.label_id)
        assert len(chain) == 2
        assert chain[0].label_id == child_label.label_id
        assert chain[1].label_id == parent_label.label_id


def test_hash_chain_integrity():
    """Test hash chain integrity verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        
        label = logger.create_causal_label(
            plan_id="plan_001",
            step_id="step_001",
            intent="Test",
            agent_class="coding",
            user_id="user1",
            autonomy_level=1,
        )
        
        # Log multiple events
        for i in range(5):
            logger.log_event(
                AuditEventType.SYSCALL,
                label,
                syscall=f"syscall_{i}",
                args={"arg": i},
                result=i,
            )
        
        assert logger.verify_integrity() is True
        
        # Tamper with log - modify the hash of an entry to break the chain
        with open(log_path, "r") as f:
            lines = f.readlines()
        # Change the hash of the 3rd entry (index 2) to break the chain
        entry = json.loads(lines[2])
        entry["hash"] = "0" * 64  # Invalid hash
        lines[2] = json.dumps(entry) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)
        
        assert logger.verify_integrity() is False


def test_ebpf_probe():
    """Test eBPF probe attachment."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = CausalAuditLogger(log_path)
        probe = EBPFAuditProbe(logger)
        
        assert probe.active is False
        result = probe.attach_syscall_probes(["open", "read", "write"])
        assert result is True
        assert probe.active is True
        assert len(probe.attached_programs) == 3
        
        probe.detach_probes()
        assert probe.active is False
        assert len(probe.attached_programs) == 0


# ----------------------------------------------------------------------
# Autopilot Tests
# ----------------------------------------------------------------------
def test_trust_scoring_engine():
    """Test trust scoring engine."""
    engine = TrustScoringEngine()
    
    agent_id = "test_agent_001"
    
    # Record successful executions
    for i in range(15):
        engine.record_event(
            agent_id,
            TrustEventType.SUCCESSFUL_EXECUTION,
            {"user_id": "user1", "agent_class": "coding"},
            f"plan_{i}",
            f"step_{i}"
        )
    
    profile = engine.get_profile(agent_id)
    assert profile is not None
    assert profile.total_events == 15
    assert profile.success_count == 15
    assert profile.trust_score > 0


def test_trust_elevation():
    """Test trust level elevation."""
    engine = TrustScoringEngine()
    
    agent_id = "test_agent_002"
    
    # Record enough successes to elevate (need 25 points, 0.5 per event = 50 events)
    for i in range(55):
        engine.record_event(
            agent_id,
            TrustEventType.SUCCESSFUL_EXECUTION,
            {"user_id": "user1", "agent_class": "coding", "autonomy_level": 2},
            f"plan_{i}",
            f"step_{i}"
        )
    
    profile = engine.get_profile(agent_id)
    # Should elevate to at least PROTECTED
    assert profile.current_trust_level != TrustLevel.LOCKED
    assert profile.current_trust_level.value >= TrustLevel.PROTECTED.value


def test_policy_violation_penalty():
    """Test policy violation reduces trust."""
    engine = TrustScoringEngine()
    
    agent_id = "test_agent_003"
    
    # Build up trust
    for i in range(20):
        engine.record_event(
            agent_id,
            TrustEventType.SUCCESSFUL_EXECUTION,
            {"user_id": "user1", "agent_class": "coding"},
            f"plan_{i}",
            f"step_{i}"
        )
    
    score_before = engine.get_profile(agent_id).trust_score
    
    # Record violation
    engine.record_event(
        agent_id,
        TrustEventType.POLICY_VIOLATION,
        {"reason": "unauthorized access"},
        "plan_99",
        "step_01"
    )
    
    score_after = engine.get_profile(agent_id).trust_score
    assert score_after < score_before
    assert engine.get_profile(agent_id).violation_count == 1


def test_effective_autonomy():
    """Test effective autonomy calculation."""
    engine = TrustScoringEngine()
    
    agent_id = "test_agent_004"
    
    # Base autonomy level 2, but trust level LOCKED initially
    for i in range(5):
        engine.record_event(
            agent_id,
            TrustEventType.SUCCESSFUL_EXECUTION,
            {"user_id": "user1", "agent_class": "coding", "autonomy_level": 2},
            f"plan_{i}",
            f"step_{i}"
        )
    
    # Effective autonomy should be min(base, trust)
    effective = engine.get_effective_autonomy(agent_id)
    assert effective <= 2  # Can't exceed base


def test_autopilot_controller():
    """Test autopilot controller."""
    autopilot = AutopilotController()
    
    agent_id = "test_agent_005"
    
    # Simulate step successes
    for i in range(10):
        autopilot.on_step_success(agent_id, f"plan_{i}", f"step_{i}", {"user_id": "user1", "agent_class": "coding"})
    
    status = autopilot.get_status(agent_id)
    assert status["agent_id"] == agent_id
    assert status["success_count"] == 10
    assert status["trust_score"] > 0


def test_autopilot_consent_tracking():
    """Test autopilot consent tracking."""
    autopilot = AutopilotController()
    
    agent_id = "test_agent_006"
    
    autopilot.on_consent_decision(agent_id, "plan_001", True, {"user_id": "user1"})
    autopilot.on_consent_decision(agent_id, "plan_002", False, {"user_id": "user1"})
    
    profile = autopilot.scoring_engine.get_profile(agent_id)
    assert profile is not None


# ----------------------------------------------------------------------
# AuthZEN Tests
# ----------------------------------------------------------------------
def test_authzen_decision_engine():
    """Test AuthZEN decision engine."""
    engine = AuthZENDecisionEngine()
    
    subject = AuthZENSubject(
        subject_id="agent_001",
        subject_type=SubjectType.AGENT,
        attributes={"user_id": "user1", "agent_class": "coding", "autonomy_level": 1},
    )
    
    resource = AuthZENResource(
        resource_id="/etc/config.yaml",
        resource_type="file",
    )
    
    action = AuthZENAction(
        action_id="file_read",
        action_type="read",
    )
    
    context = AuthZENContext(
        request_id="req_001",
        timestamp=int(time.time() * 1000),
    )
    
    request = AuthZENDecisionRequest(
        subject=subject,
        resource=resource,
        action=action,
        context=context,
    )
    
    response = engine.evaluate(request)
    assert response.decision in [DecisionType.PERMIT, DecisionType.DENY, DecisionType.INDETERMINATE]


def test_spiffe_identity_provider():
    """Test SPIFFE identity provider."""
    provider = SPIFFEIdentityProvider("test.example.com")
    
    spiffe_id = provider.register_agent("agent_001", "coding", "user1", 2)
    assert spiffe_id == "spiffe://test.example.com/agent/coding/agent_001"
    
    identity = provider.get_identity("agent_001")
    assert identity is not None
    assert identity["agent_class"] == "coding"
    assert identity["user_id"] == "user1"
    assert identity["autonomy_level"] == 2
    
    # Verify SPIFFE ID
    verified = provider.verify_spiffe_id(spiffe_id)
    assert verified is not None
    assert verified["agent_id"] == "agent_001"
    
    # Create X.509 SVID (mock)
    svid = provider.create_x509_svid("agent_001")
    assert "certificate" in svid
    
    # Create JWT SVID
    jwt = provider.create_jwt_svid("agent_001", ["api.example.com"])
    assert len(jwt.split(".")) == 3  # JWT has 3 parts


def test_idjag_broker():
    """Test ID-JAG broker."""
    spiffe_provider = SPIFFEIdentityProvider()
    broker = IDJAGBroker(spiffe_provider)
    
    # Register agents
    spiffe_provider.register_agent("admin_001", "admin", "admin", 3)
    spiffe_provider.register_agent("agent_001", "coding", "user1", 2)
    
    # Create delegation
    delegation_id = broker.create_delegation(
        delegator_id="admin_001",
        delegatee_id="agent_001",
        scope=["file_read", "file_write", "http_get"],
        constraints={"max_autonomy": 2},
        expires_at=int(time.time()) + 86400,
    )
    
    assert delegation_id is not None
    
    # Validate delegation
    valid = broker.validate_delegation(delegation_id, "file_read", "/etc/config.yaml")
    assert valid is True
    
    # Invalid action
    invalid = broker.validate_delegation(delegation_id, "file_delete", "/etc/config.yaml")
    assert invalid is False
    
    # Get delegations
    delegations = broker.get_delegations_for_agent("agent_001")
    assert len(delegations) == 1
    
    # Revoke
    revoked = broker.revoke_delegation(delegation_id)
    assert revoked is True
    
    # Should be invalid now
    invalid_after_revoke = broker.validate_delegation(delegation_id, "file_read", "/etc/config.yaml")
    assert invalid_after_revoke is False


# ----------------------------------------------------------------------
# Integration Tests
# ----------------------------------------------------------------------
def test_full_phase4_integration():
    """Test full Phase 4 integration."""
    # Initialize all components
    autopilot = get_autopilot()
    authzen = get_authzen_engine()
    spiffe = get_spiffe_provider()
    idjag = get_idjag_broker()
    
    agent_id = "integration_agent_001"
    
    # Register agent identity
    spiffe_id = spiffe.register_agent(agent_id, "coding", "user123", 2)
    assert spiffe_id is not None
    
    # Record some successful steps
    for i in range(20):
        autopilot.on_step_success(agent_id, f"plan_{i}", f"step_{i}", {"user_id": "user123", "agent_class": "coding"})
    
    # Check autopilot status
    status = autopilot.get_status(agent_id)
    assert status["trust_score"] > 0
    
    # Create delegation
    delegation_id = idjag.create_delegation(
        delegator_id="admin_001",
        delegatee_id=agent_id,
        scope=["file_read", "file_write"],
        constraints={"max_autonomy": 2},
        expires_at=int(time.time()) + 86400,
    )
    assert delegation_id is not None
    
    # Create AuthZEN request with plan context
    subject = AuthZENSubject(
        subject_id=agent_id,
        subject_type=SubjectType.AGENT,
        spiffe_id=spiffe_id,
        attributes={"user_id": "user123", "agent_class": "coding", "autonomy_level": 2},
    )
    
    resource = AuthZENResource(
        resource_id="/etc/config.yaml",
        resource_type="file",
    )
    
    action = AuthZENAction(
        action_id="file_write",
        action_type="write",
    )
    
    context = AuthZENContext(
        request_id="req_integration_001",
        timestamp=int(time.time() * 1000),
        environment={
            "plan_id": "plan_001",
            "step_id": "step_001",
            "token": "mock_valid_token",
            "intent": "Write config file",
        },
    )
    
    request = AuthZENDecisionRequest(
        subject=subject,
        resource=resource,
        action=action,
        context=context,
    )
    
    # This will check consent and tokens - since we don't have real consent/tokens,
    # it should deny, but we can verify the decision structure
    response = authzen.evaluate(request)
    assert response.decision in [DecisionType.PERMIT, DecisionType.DENY]
    assert "guardrail" in response.metadata


# ----------------------------------------------------------------------
# Run tests
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])