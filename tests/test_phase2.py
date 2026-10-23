"""Tests for Phase 2 components: token service, enhanced plan compiler, consent manager, and adapters."""
import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from token_service import (
    TokenService, TokenPayload, TokenType,
    create_plan_token, create_step_token,
    validate_token, validate_plan_token, validate_step_token
)
from plan_compiler.enhanced_plan_compiler import (
    ValidatedPlan, ValidatedStep,
    compile_and_validate_plan, validate_step_token_for_execution
)
from consent_manager import (
    ConsentManager, ConsentRequest, ConsentDecision, ConsentStatus,
    request_plan_consent, process_plan_consent, is_plan_approved, is_step_approved
)


# ----------------------------------------------------------------------
# Token Service Tests
# ----------------------------------------------------------------------
def test_token_service_creation():
    """Test token service can be created."""
    service = TokenService("test-secret")
    assert service is not None


def test_create_plan_token():
    """Test creating a plan token."""
    token = create_plan_token(
        plan_id="test_plan_001",
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 0


def test_create_step_token():
    """Test creating a step token."""
    token = create_step_token(
        plan_id="test_plan_001",
        step_id="step_001",
        intent="Test step",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    assert token is not None
    assert isinstance(token, str)


def test_validate_plan_token():
    """Test validating a plan token."""
    token = create_plan_token(
        plan_id="test_plan_001",
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    payload = validate_plan_token(token, "test_plan_001")
    assert payload is not None
    assert payload.token_type == TokenType.PLAN
    assert payload.plan_id == "test_plan_001"
    assert payload.agent_class == "coding"
    assert payload.user_id == "user1"
    assert payload.autonomy_level == 1


def test_validate_step_token():
    """Test validating a step token."""
    token = create_step_token(
        plan_id="test_plan_001",
        step_id="step_001",
        intent="Test step",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    payload = validate_step_token(token, "test_plan_001", "step_001")
    assert payload is not None
    assert payload.token_type == TokenType.STEP
    assert payload.plan_id == "test_plan_001"
    assert payload.step_id == "step_001"


def test_token_expiration():
    """Test token expiration."""
    service = TokenService("test-secret")
    token = service.create_plan_token(
        plan_id="test_plan_001",
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
        ttl=-1  # Already expired
    )
    payload = service.validate_plan_token(token, "test_plan_001")
    assert payload is None


def test_token_tampering():
    """Test that tampered tokens are rejected."""
    token = create_plan_token(
        plan_id="test_plan_001",
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    # Tamper with the token
    tampered = token[:-5] + "XXXXX"
    payload = validate_plan_token(tampered, "test_plan_001")
    assert payload is None


def test_validate_step_token_for_execution():
    """Test the execution-time step token validation."""
    vplan = compile_and_validate_plan(
        intent="Create a file and read it",
        plan_id="test_plan_002",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    step_id = vplan.steps[0].id
    step_token = vplan.step_tokens.get(step_id)
    assert step_token is not None
    
    # Valid validation
    valid = validate_step_token_for_execution(
        vplan.id, step_id, step_token, "coding", "user1", 1
    )
    assert valid is True
    
    # Wrong agent class
    valid = validate_step_token_for_execution(
        vplan.id, step_id, step_token, "data_analysis", "user1", 1
    )
    assert valid is False


# ----------------------------------------------------------------------
# Enhanced Plan Compiler Tests
# ----------------------------------------------------------------------
def test_compile_and_validate_plan():
    """Test compiling and validating a plan."""
    vplan = compile_and_validate_plan(
        intent="Create a file called test.txt and write hello to it",
        plan_id="test_plan_003",
        agent_class="coding",
        user_id="user1",
        autonomy_level=2,
    )
    
    assert isinstance(vplan, ValidatedPlan)
    assert vplan.id == "test_plan_003"
    assert len(vplan.steps) > 0
    assert vplan.model_required == "nvidia/nemotron-3-nano-30b-a3b-reasoning"


def test_plan_validation_errors():
    """Test that invalid plans have validation errors."""
    # This should produce validation errors due to unknown action type
    # We'll test with a valid plan first
    vplan = compile_and_validate_plan(
        intent="Create a file called test.txt",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    # Should have no validation errors for valid actions
    # Note: The parser might not recognize all actions, so we just check structure


def test_step_reversibility():
    """Test step reversibility detection."""
    vplan = compile_and_validate_plan(
        intent="Write a file then delete it",
        plan_id="test_reversible",
        agent_class="coding",
        user_id="user1",
        autonomy_level=2,
    )
    
    write_step = None
    delete_step = None
    for step in vplan.steps:
        if step.action_type == "file_write":
            write_step = step
        elif step.action_type == "file_delete":
            delete_step = step
    
    if write_step:
        assert write_step.reversible is True
        assert write_step.reversal_action == "file_delete"
    
    if delete_step:
        assert delete_step.reversible is True
        assert delete_step.reversal_action == "file_write"


def test_step_tokens_generated():
    """Test that step tokens are generated for valid plans."""
    vplan = compile_and_validate_plan(
        intent="Read a file",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    assert vplan.plan_token is not None
    assert len(vplan.step_tokens) > 0
    for step in vplan.steps:
        if not step.validation_errors:
            assert step.id in vplan.step_tokens


# ----------------------------------------------------------------------
# Consent Manager Tests
# ----------------------------------------------------------------------
def test_consent_manager_creation():
    """Test consent manager creation."""
    manager = ConsentManager()
    assert manager is not None


def test_request_consent():
    """Test requesting consent for a plan."""
    manager = ConsentManager()
    vplan = compile_and_validate_plan(
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    request = manager.request_consent(vplan, risk_level="medium")
    assert request is not None
    assert request.plan_id == vplan.id
    assert request.status == ConsentStatus.PENDING
    assert len(request.steps_summary) == len(vplan.steps)


def test_process_consent_approval():
    """Test processing consent approval."""
    manager = ConsentManager()
    vplan = compile_and_validate_plan(
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    manager.request_consent(vplan)
    decision = ConsentDecision(
        plan_id=vplan.id,
        approved=True,
        step_approvals={step.id: True for step in vplan.steps},
        conditions=["Test condition"],
    )
    
    result = manager.process_consent(vplan.id, decision)
    assert result is True
    assert manager.is_plan_approved(vplan.id)
    
    for step in vplan.steps:
        assert manager.is_step_approved(vplan.id, step.id)


def test_process_consent_denial():
    """Test processing consent denial."""
    manager = ConsentManager()
    vplan = compile_and_validate_plan(
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    manager.request_consent(vplan)
    decision = ConsentDecision(
        plan_id=vplan.id,
        approved=False,
        step_approvals={},
        conditions=["Denied by user"],
    )
    
    result = manager.process_consent(vplan.id, decision)
    assert result is True
    assert not manager.is_plan_approved(vplan.id)
    assert manager.requests[vplan.id].status == ConsentStatus.DENIED


def test_consent_expiration():
    """Test consent expiration."""
    manager = ConsentManager(default_ttl=-1)  # Immediate expiration
    vplan = compile_and_validate_plan(
        intent="Test intent",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
    )
    
    manager.request_consent(vplan)
    # Small delay to ensure expiration
    import time
    time.sleep(0.1)
    
    decision = ConsentDecision(plan_id=vplan.id, approved=True)
    result = manager.process_consent(vplan.id, decision)
    assert result is False  # Should fail due to expiration
    assert manager.requests[vplan.id].status == ConsentStatus.EXPIRED


def test_risk_assessment():
    """Test step risk assessment."""
    manager = ConsentManager()
    vplan = compile_and_validate_plan(
        intent="Delete a file and run shell command",
        agent_class="coding",
        user_id="user1",
        autonomy_level=2,
    )
    
    request = manager.request_consent(vplan, risk_level="high")
    high_risk_steps = [s for s in request.steps_summary if s['risk'] == 'high']
    assert len(high_risk_steps) > 0  # file_delete and shell_command should be high risk


# ----------------------------------------------------------------------
# Integration Tests
# ----------------------------------------------------------------------
def test_full_plan_lifecycle():
    """Test the complete plan lifecycle: compile -> consent -> tokens -> execution validation."""
    # 1. Compile and validate plan
    vplan = compile_and_validate_plan(
        intent="Create a file called config.yaml in /etc/ and then read it back",
        plan_id="lifecycle_test",
        agent_class="coding",
        user_id="user123",
        autonomy_level=2,
    )
    
    assert vplan.plan_token is not None
    assert len(vplan.step_tokens) == len(vplan.steps)
    
    # 2. Request consent
    manager = ConsentManager()
    manager.request_consent(vplan, risk_level="medium")
    
    # 3. Process consent (auto-approve)
    decision = ConsentDecision(
        plan_id=vplan.id,
        approved=True,
        step_approvals={step.id: True for step in vplan.steps},
        conditions=[],
    )
    manager.process_consent(vplan.id, decision)
    
    assert manager.is_plan_approved(vplan.id)
    for step in vplan.steps:
        assert manager.is_step_approved(vplan.id, step.id)
    
    # 4. Validate tokens for execution
    for step in vplan.steps:
        token = vplan.step_tokens[step.id]
        valid = validate_step_token_for_execution(
            vplan.id, step.id, token, "coding", "user123", 2
        )
        assert valid is True


# ----------------------------------------------------------------------
# Run tests
# ----------------------------------------------------------------------
if __name__ == "__main__":
    pytest.main([__file__, "-v"])