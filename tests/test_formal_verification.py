"""Tests for Phase 2: Formal Verification Core."""
import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from guardrail.formal_verification.policy_language import (
    PolicySet, PolicyRule, PolicyCondition, PolicyExpression,
    PolicyVariable, PolicyType, LogicalOperator, ComparisonOperator,
    create_safety_policy_set, create_resource_policy_set, create_compliance_policy_set,
    condition, and_expr, or_expr, not_expr, implies, variable,
)
from guardrail.formal_verification.verifier import (
    VerificationResult, VerificationReport, VerificationPipeline,
    create_verifier, Z3Verifier, MockVerifier,
)


def test_policy_variable_creation():
    """Test PolicyVariable creation."""
    var = variable("action_type", "string", "Type of action")
    assert var.name == "action_type"
    assert var.type == "string"
    assert var.description == "Type of action"


def test_policy_condition_creation():
    """Test PolicyCondition creation."""
    cond = condition("autonomy_level", ComparisonOperator.GE, 1)
    assert cond.variable == "autonomy_level"
    assert cond.operator == ComparisonOperator.GE
    assert cond.value == 1


def test_policy_expression_creation():
    """Test PolicyExpression creation with helpers."""
    cond1 = condition("autonomy_level", ComparisonOperator.GE, 1)
    cond2 = condition("user_consent", ComparisonOperator.EQ, True)
    
    expr = and_expr(cond1, cond2)
    assert expr.operator == LogicalOperator.AND
    assert len(expr.operands) == 2
    
    expr_or = or_expr(cond1, cond2)
    assert expr_or.operator == LogicalOperator.OR
    
    expr_not = not_expr(cond1)
    assert expr_not.operator == LogicalOperator.NOT
    assert len(expr_not.operands) == 1
    
    expr_implies = implies(cond1, cond2)
    assert expr_implies.operator == LogicalOperator.IMPLIES


def test_policy_rule_creation():
    """Test PolicyRule creation."""
    rule = PolicyRule(
        id="test_001",
        name="Test Rule",
        policy_type=PolicyType.SAFETY,
        description="Test rule description",
        variables=[
            variable("action_type", "string"),
            variable("autonomy_level", "int"),
        ],
        precondition=None,
        condition=condition("autonomy_level", ComparisonOperator.GE, 1),
        action="deny",
        priority=50,
    )
    assert rule.id == "test_001"
    assert rule.name == "Test Rule"
    assert rule.action == "deny"
    assert rule.priority == 50


def test_policy_set_creation():
    """Test PolicySet creation."""
    rule = PolicyRule(
        id="test_001",
        name="Test Rule",
        policy_type=PolicyType.SAFETY,
        description="Test rule description",
        variables=[variable("action_type", "string")],
        precondition=None,
        condition=condition("action_type", ComparisonOperator.EQ, "file_read"),
        action="allow",
    )
    
    policy_set = PolicySet(
        id="test_set",
        name="Test Policy Set",
        version="1.0.0",
        rules=[rule],
    )
    assert policy_set.id == "test_set"
    assert len(policy_set.rules) == 1


def test_predefined_safety_policy():
    """Test predefined safety policy set."""
    safety = create_safety_policy_set()
    assert safety.id == "guardrail_safety_v1"
    assert len(safety.rules) == 5
    
    # Check specific rules exist
    rule_ids = {r.id for r in safety.rules}
    assert "safety_001" in rule_ids  # Block Admin Actions Without Consent
    assert "safety_002" in rule_ids  # High Risk Actions Require Approval
    assert "safety_003" in rule_ids  # Autonomy Level Enforcement
    assert "safety_004" in rule_ids  # Path Traversal Prevention
    assert "safety_005" in rule_ids  # Sensitive Path Protection


def test_predefined_resource_policy():
    """Test predefined resource policy set."""
    resource = create_resource_policy_set()
    assert resource.id == "guardrail_resource_v1"
    assert len(resource.rules) == 4
    
    rule_ids = {r.id for r in resource.rules}
    assert "resource_001" in rule_ids  # CPU Limit
    assert "resource_002" in rule_ids  # Memory Limit
    assert "resource_003" in rule_ids  # Network Rate Limit
    assert "resource_004" in rule_ids  # Execution Timeout


def test_predefined_compliance_policy():
    """Test predefined compliance policy set."""
    compliance = create_compliance_policy_set()
    assert compliance.id == "guardrail_compliance_v1"
    assert len(compliance.rules) == 2
    
    rule_ids = {r.id for r in compliance.rules}
    assert "compliance_001" in rule_ids  # AI Act - High Risk AI
    assert "compliance_002" in rule_ids  # GDPR - Special Category Data


def test_verifier_creation():
    """Test verifier factory."""
    verifier = create_verifier()
    assert verifier is not None
    # Should be Z3Verifier since z3-solver is installed
    assert isinstance(verifier, Z3Verifier)


def test_safety_policy_verification():
    """Test safety policy verification."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    report = verifier.verify_policy_set(safety)
    assert report.result == VerificationResult.SAT
    assert report.policy_id == "guardrail_safety_v1"
    assert report.execution_time_ms > 0


def test_resource_policy_verification():
    """Test resource policy verification."""
    verifier = create_verifier()
    resource = create_resource_policy_set()
    
    report = verifier.verify_policy_set(resource)
    assert report.result == VerificationResult.SAT


def test_compliance_policy_verification():
    """Test compliance policy verification."""
    verifier = create_verifier()
    compliance = create_compliance_policy_set()
    
    report = verifier.verify_policy_set(compliance)
    assert report.result == VerificationResult.SAT


def test_action_verification_file_read():
    """Test file_read action verification."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    # file_read at L0 should be allowed
    action = {
        "action_type": "file_read",
        "autonomy_level": 0,
        "user_consent": False,
        "requires_admin": False,
    }
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is True
    assert "Allowed" in reason


def test_action_verification_file_write_l0():
    """Test file_write at L0 should be denied."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    # file_write at L0 should be denied (needs L1)
    action = {
        "action_type": "file_write",
        "autonomy_level": 0,
        "user_consent": False,
        "requires_admin": False,
    }
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is False


def test_action_verification_file_write_l1():
    """Test file_write at L1 should be allowed."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    action = {
        "action_type": "file_write",
        "autonomy_level": 1,
        "user_consent": False,
        "requires_admin": False,
    }
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is True


def test_action_verification_shell_command():
    """Test shell_command action verification."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    # shell_command at L2 should be allowed
    action = {
        "action_type": "shell_command",
        "autonomy_level": 2,
        "user_consent": False,
        "requires_admin": False,
    }
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is True
    
    # shell_command at L1 should be denied
    action["autonomy_level"] = 1
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is False


def test_action_verification_admin_requires_consent():
    """Test admin actions require consent."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    # file_delete (admin) with consent at L3 should require approval
    action = {
        "action_type": "file_delete",
        "autonomy_level": 3,
        "user_consent": True,
        "requires_admin": True,
    }
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is True
    assert "Requires approval" in reason
    
    # file_delete without consent at L3 should be denied
    action["user_consent"] = False
    allowed, reason, rules = verifier.verify_action(safety, action)
    assert allowed is False


def test_rule_conflicts():
    """Test rule conflict detection."""
    verifier = create_verifier()
    safety = create_safety_policy_set()
    
    conflicts = verifier.check_rule_conflicts(safety)
    # Safety rules should not have direct conflicts
    # May have priority conflicts
    assert isinstance(conflicts, list)


def test_verification_pipeline():
    """Test verification pipeline with multiple policy sets."""
    verifier = create_verifier()
    pipeline = VerificationPipeline(verifier)
    
    safety = create_safety_policy_set()
    resource = create_resource_policy_set()
    compliance = create_compliance_policy_set()
    
    pipeline.add_policy_set(safety)
    pipeline.add_policy_set(resource)
    pipeline.add_policy_set(compliance)
    
    # Verify all policy sets
    results = pipeline.run_all()
    assert len(results) == 3
    for pid, report in results.items():
        assert report.result == VerificationResult.SAT
    
    # Check conflicts
    all_conflicts = pipeline.check_all_conflicts()
    assert len(all_conflicts) == 3
    
    # Verify action across all policies
    action = {
        "action_type": "file_write",
        "autonomy_level": 1,
        "user_consent": False,
        "requires_admin": False,
        "cpu_usage": 50.0,
        "memory_mb": 512,
        "network_mbps": 10.0,
        "execution_time_s": 60,
        "is_high_risk_ai": False,
    }
    allowed, reasons, rules = pipeline.verify_action_across_sets(action)
    assert isinstance(allowed, bool)
    assert len(reasons) == 3  # One per policy set


def test_policy_to_smt_lib():
    """Test SMT-LIB export."""
    safety = create_safety_policy_set()
    smt_lib = safety.to_smt_lib()
    
    assert "(set-logic ALL)" in smt_lib
    assert "Guardrail Safety Policy Set v1" in smt_lib
    assert "(check-sat)" in smt_lib
    assert "(get-model)" in smt_lib
    assert "declare-const" in smt_lib


def test_mock_verifier():
    """Test MockVerifier when Z3 not available."""
    mock = MockVerifier()
    safety = create_safety_policy_set()
    
    report = mock.verify_policy_set(safety)
    assert report.result == VerificationResult.SAT
    assert "Mock verification" in report.message
    
    # Test action verification
    action = {"action_type": "file_read", "autonomy_level": 0}
    allowed, reason, rules = mock.verify_action(safety, action)
    assert allowed is True


if __name__ == "__main__":
    # Run all tests
    test_policy_variable_creation()
    print("✓ test_policy_variable_creation")
    
    test_policy_condition_creation()
    print("✓ test_policy_condition_creation")
    
    test_policy_expression_creation()
    print("✓ test_policy_expression_creation")
    
    test_policy_rule_creation()
    print("✓ test_policy_rule_creation")
    
    test_policy_set_creation()
    print("✓ test_policy_set_creation")
    
    test_predefined_safety_policy()
    print("✓ test_predefined_safety_policy")
    
    test_predefined_resource_policy()
    print("✓ test_predefined_resource_policy")
    
    test_predefined_compliance_policy()
    print("✓ test_predefined_compliance_policy")
    
    test_verifier_creation()
    print("✓ test_verifier_creation")
    
    test_safety_policy_verification()
    print("✓ test_safety_policy_verification")
    
    test_resource_policy_verification()
    print("✓ test_resource_policy_verification")
    
    test_compliance_policy_verification()
    print("✓ test_compliance_policy_verification")
    
    test_action_verification_file_read()
    print("✓ test_action_verification_file_read")
    
    test_action_verification_file_write_l0()
    print("✓ test_action_verification_file_write_l0")
    
    test_action_verification_file_write_l1()
    print("✓ test_action_verification_file_write_l1")
    
    test_action_verification_shell_command()
    print("✓ test_action_verification_shell_command")
    
    test_action_verification_admin_requires_consent()
    print("✓ test_action_verification_admin_requires_consent")
    
    test_rule_conflicts()
    print("✓ test_rule_conflicts")
    
    test_verification_pipeline()
    print("✓ test_verification_pipeline")
    
    test_policy_to_smt_lib()
    print("✓ test_policy_to_smt_lib")
    
    test_mock_verifier()
    print("✓ test_mock_verifier")
    
    print("\n=== All Phase 2 tests passed! ===")