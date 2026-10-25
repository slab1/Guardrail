"""Tests for Phase 1.2 Policy Language Features."""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from guardrail.formal_verification.policy_language import (
    PolicySet, PolicyRule, PolicyCondition, PolicyExpression, TemporalPolicyCondition,
    PolicyVariable, PolicyType, LogicalOperator, ComparisonOperator, TemporalOperator,
    condition, and_expr, or_expr, not_expr, implies, variable,
    temporal_always, temporal_eventually, temporal_next,
)


def test_regex_support():
    """Test regex support in policy conditions."""
    var = variable("file_path", "string")
    
    # STARTS_WITH operator
    cond1 = condition("file_path", ComparisonOperator.STARTS_WITH, "/etc/")
    assert "str.prefixof" in cond1.to_smt()
    
    # ENDS_WITH operator
    cond2 = condition("file_path", ComparisonOperator.ENDS_WITH, ".log")
    assert "str.suffixof" in cond2.to_smt()
    
    # REGEX operator
    cond3 = condition("file_path", ComparisonOperator.REGEX, r"/var/log/.*\.log")
    assert "str.in_re" in cond3.to_smt()
    assert "re.++" in cond3.to_smt()
    
    print("✓ Regex support tests passed")


def test_policy_composition_forall_exists():
    """Test policy composition with FORALL and EXISTS quantifiers."""
    # FORALL quantifier
    cond1 = condition("x", ComparisonOperator.GT, 0)
    expr_forall = PolicyExpression(LogicalOperator.FORALL, [cond1])
    smt = expr_forall.to_smt()
    assert "forall" in smt
    assert "Int" in smt
    
    # EXISTS quantifier
    expr_exists = PolicyExpression(LogicalOperator.EXISTS, [cond1])
    smt = expr_exists.to_smt()
    assert "exists" in smt
    assert "Int" in smt
    
    print("✓ Policy composition with quantifiers tests passed")


def test_nested_conditions():
    """Test nested conditions with composition operators."""
    cond1 = condition("a", ComparisonOperator.EQ, 1)
    cond2 = condition("b", ComparisonOperator.EQ, 2)
    cond3 = condition("c", ComparisonOperator.EQ, 3)
    
    # Nested AND-OR
    expr = and_expr(cond1, or_expr(cond2, cond3))
    smt = expr.to_smt()
    assert "(and" in smt
    assert "(or" in smt
    
    # Triple nested
    expr2 = and_expr(
        or_expr(cond1, cond2),
        not_expr(cond3)
    )
    smt2 = expr2.to_smt()
    assert smt2.count("(and") == 1
    assert smt2.count("(or") == 1
    assert "(not" in smt2
    
    print("✓ Nested conditions tests passed")


def test_temporal_operators():
    """Test temporal logic operators."""
    cond = condition("access_granted", ComparisonOperator.EQ, True)
    
    # ALWAYS operator
    always_cond = temporal_always(cond, duration=3600)
    smt = always_cond.to_smt()
    assert "ALWAYS" in smt
    assert "3600s" in smt
    
    # EVENTUALLY operator
    eventually_cond = temporal_eventually(cond, duration=60)
    smt = eventually_cond.to_smt()
    assert "EVENTUALLY" in smt
    assert "60s" in smt
    
    # NEXT operator
    next_cond = temporal_next(cond)
    smt = next_cond.to_smt()
    assert "NEXT" in smt
    
    print("✓ Temporal operators tests passed")


def test_temporal_in_policy():
    """Test temporal conditions in actual policy rules."""
    var = variable("time_since_last_access", "int")
    var2 = variable("max_allowed_duration", "int")
    
    cond = condition("time_since_last_access", ComparisonOperator.LT, 
                    PolicyCondition("max_allowed_duration", ComparisonOperator.EQ, 0).variable)
    
    temporal_cond = temporal_always(cond, duration=86400)
    
    rule = PolicyRule(
        id="temporal_001",
        name="Access Timeout Policy",
        policy_type=PolicyType.SAFETY,
        description="Access must remain valid for 24 hours",
        variables=[var, var2],
        precondition=None,
        condition=temporal_cond,
        action="deny",
        priority=50
    )
    
    smt = rule.to_smt()
    assert "ALWAYS" in smt
    assert "86400s" in smt
    
    print("✓ Temporal policy integration tests passed")


def test_comparison_operators():
    """Test all comparison operators work correctly."""
    operators = [
        (ComparisonOperator.EQ, "=="),
        (ComparisonOperator.NE, "!="),
        (ComparisonOperator.LT, "<"),
        (ComparisonOperator.LE, "<="),
        (ComparisonOperator.GT, ">"),
        (ComparisonOperator.GE, ">="),
        (ComparisonOperator.IN, "in"),
        (ComparisonOperator.NOT_IN, "not_in"),
        (ComparisonOperator.CONTAINS, "contains"),
        (ComparisonOperator.MATCHES, "matches"),
        (ComparisonOperator.STARTS_WITH, "starts_with"),
        (ComparisonOperator.ENDS_WITH, "ends_with"),
        (ComparisonOperator.REGEX, "regex"),
    ]
    
    for op, _ in operators:
        cond = PolicyCondition("test_var", op, "test_value")
        smt = cond.to_smt()
        assert len(smt) > 0, f"Operator {op} failed"
    
    print(f"✓ All {len(operators)} comparison operators working")


def test_logical_operators():
    """Test all logical operators work correctly."""
    cond1 = condition("a", ComparisonOperator.EQ, 1)
    cond2 = condition("b", ComparisonOperator.EQ, 2)
    
    operators = [
        (LogicalOperator.AND, and_expr(cond1, cond2)),
        (LogicalOperator.OR, or_expr(cond1, cond2)),
        (LogicalOperator.NOT, not_expr(cond1)),
        (LogicalOperator.IMPLIES, implies(cond1, cond2)),
        (LogicalOperator.IFF, PolicyExpression(LogicalOperator.IFF, [cond1, cond2])),
        (LogicalOperator.FORALL, PolicyExpression(LogicalOperator.FORALL, [cond1])),
        (LogicalOperator.EXISTS, PolicyExpression(LogicalOperator.EXISTS, [cond1])),
    ]
    
    for op, expr in operators:
        smt = expr.to_smt()
        assert len(smt) > 0, f"Operator {op} failed"
    
    print(f"✓ All {len(operators)} logical operators working")


def test_policy_set_with_new_features():
    """Test policy set creation with new features."""
    var = variable("file_path", "string")
    var2 = variable("access_time", "int")
    
    # Regex condition
    regex_cond = condition("file_path", ComparisonOperator.REGEX, r"/sensitive/.*")
    
    # Temporal condition
    time_cond = condition("access_time", ComparisonOperator.GT, 0)
    temporal_cond = temporal_always(time_cond, duration=3600)
    
    # Combined expression
    combined = and_expr(regex_cond, temporal_cond)
    
    rule = PolicyRule(
        id="test_001",
        name="Sensitive File Access",
        policy_type=PolicyType.SECURITY,
        description="Access to sensitive files must be temporary",
        variables=[var, var2],
        precondition=None,
        condition=combined,
        action="require_approval",
        priority=100
    )
    
    policy_set = PolicySet(
        id="test_set",
        name="Test Policy Set",
        version="1.0",
        rules=[rule]
    )
    
    smt_lib = policy_set.to_smt_lib()
    assert "str.in_re" in smt_lib
    assert "ALWAYS" in smt_lib
    assert "3600s" in smt_lib
    
    print("✓ Policy set with new features tests passed")


if __name__ == "__main__":
    test_regex_support()
    test_policy_composition_forall_exists()
    test_nested_conditions()
    test_temporal_operators()
    test_temporal_in_policy()
    test_comparison_operators()
    test_logical_operators()
    test_policy_set_with_new_features()
    print("\n✅ All Phase 1.2 Policy Language Features tests passed!")
