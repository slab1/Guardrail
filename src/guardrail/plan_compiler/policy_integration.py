"""Policy Integration for Plan Compiler

Integrates formal verification results into plan compilation.
Adds policy compliance checks during plan validation.
Creates policy-aware plan optimization.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from enum import Enum
import logging
import hashlib

from guardrail.plan_compiler.enhanced_plan_compiler import (
    compile_and_validate_plan, ValidatedPlan, ValidatedStep,
    VALID_ACTION_TYPES, ActionType, ResourceType,
    RESOURCE_PATTERNS, PlanValidationError,
    _validate_step_detailed, _guess_resource_type
)
from guardrail.formal_verification.verifier import (
    Z3Verifier, VerificationReport, VerificationResult,
    PolicyConflict, PolicySet, Z3_AVAILABLE
)
from guardrail.formal_verification.policy_language import (
    PolicyRule, PolicyCondition, PolicyVariable, PolicyType,
    LogicalOperator, ComparisonOperator, create_safety_policy_set,
    create_resource_policy_set, create_compliance_policy_set
)
from guardrail.formal_verification.policy_parser import PolicyParser
from guardrail.formal_verification.policy_templates import (
    render_template, get_template, list_templates
)

logger = logging.getLogger(__name__)


class PolicyComplianceStatus(Enum):
    """Policy compliance check results."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    REQUIRES_REVIEW = "requires_review"
    ERROR = "error"


@dataclass
class PolicyComplianceCheck:
    """Result of a policy compliance check."""
    status: PolicyComplianceStatus
    rule_id: str
    rule_name: str
    message: str
    severity: str = "medium"  # low, medium, high, critical
    suggested_action: Optional[str] = None


@dataclass
class PolicyValidatedPlan:
    """Plan with policy compliance validation results."""
    validated_plan: ValidatedPlan
    compliance_checks: List[PolicyComplianceCheck] = field(default_factory=list)
    verification_report: Optional[VerificationReport] = None
    conflicts: List[PolicyConflict] = field(default_factory=list)
    optimization_suggestions: List[str] = field(default_factory=list)
    
    @property
    def is_compliant(self) -> bool:
        """Check if plan is fully policy compliant."""
        return all(c.status == PolicyComplianceStatus.COMPLIANT 
                   for c in self.compliance_checks)
    
    @property
    def has_critical_issues(self) -> bool:
        """Check if any critical issues exist."""
        return any(c.severity == "critical" for c in self.compliance_checks)


class PolicyIntegration:
    """Integrates policy verification with plan compilation."""
    
    def __init__(self, policy_set: Optional[PolicySet] = None, 
                 timeout_ms: int = 5000):
        """Initialize policy integration.
        
        Args:
            policy_set: PolicySet to use for verification. If None, uses default safety set.
            timeout_ms: Z3 solver timeout in milliseconds.
        """
        if policy_set is None:
            policy_set = create_safety_policy_set()
            policy_set.rules.extend(create_resource_policy_set().rules)
            policy_set.rules.extend(create_compliance_policy_set().rules)
        
        self.policy_set = policy_set
        
        # Initialize verifier only if Z3 is available
        self.verifier = None
        if Z3_AVAILABLE:
            try:
                self.verifier = Z3Verifier(timeout_ms=timeout_ms)
            except RuntimeError:
                logger.warning("Z3 not available, formal verification disabled")
        else:
            logger.warning("Z3 not available, formal verification disabled")
        
        self.parser = PolicyParser()
        
        # Map action types to policy variables
        self.action_to_variables = {
            "shell_command": ["action_type", "user_consent", "command_type", "requires_admin", "risk_level"],
            "shell_exec": ["action_type", "user_consent", "command_type", "requires_admin", "risk_level"],
            "file_read": ["action_type", "path", "user_consent", "resource_path"],
            "file_write": ["action_type", "path", "user_consent", "resource_path"],
            "file_delete": ["action_type", "path", "user_consent", "resource_path"],
            "http_post": ["action_type", "url", "user_consent", "data_sensitivity"],
            "http_put": ["action_type", "url", "user_consent"],
            "http_delete": ["action_type", "url", "user_consent"],
            "database_update": ["action_type", "query_type", "user_consent"],
            "database_query": ["action_type", "query_type"],
        }
    
    def compile_policy_aware_plan(
        self,
        intent: str,
        plan_id: Optional[str] = None,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        policy_context: Optional[Dict[str, Any]] = None
    ) -> PolicyValidatedPlan:
        """Compile a plan with full policy validation.
        
        Args:
            intent: Natural language description of the task
            plan_id: Optional plan identifier
            agent_class: Agent class for policy enforcement
            user_id: User identifier
            autonomy_level: User's autonomy level (0-3)
            policy_context: Additional context for policy evaluation
            
        Returns:
            PolicyValidatedPlan with compliance checks and verification
        """
        if plan_id is None:
            plan_id = hashlib.sha256(intent.encode('utf-8')).hexdigest()[:8]
        
        # Step 1: Compile base plan with existing validation
        base_plan = compile_and_validate_plan(
            intent=intent,
            plan_id=plan_id,
            agent_class=agent_class,
            user_id=user_id,
            autonomy_level=autonomy_level
        )
        
        # Step 2: Check policy compliance for each step
        compliance_checks = self._check_plan_compliance(base_plan, policy_context)
        
        # Step 3: Verify policy set for conflicts
        conflicts = []
        if self.verifier:
            conflicts = self.verifier.check_rule_conflicts(self.policy_set)
        
        # Step 4: Run formal verification if policy variables are present
        verification_report = None
        if self.verifier and self._has_policy_variables(base_plan, policy_context):
            verification_report = self._verify_plan_policies(base_plan, policy_context)
        
        # Step 5: Generate optimization suggestions
        optimization_suggestions = self._generate_optimization_suggestions(
            base_plan, compliance_checks, conflicts
        )
        
        return PolicyValidatedPlan(
            validated_plan=base_plan,
            compliance_checks=compliance_checks,
            verification_report=verification_report,
            conflicts=conflicts,
            optimization_suggestions=optimization_suggestions
        )
    
    def _check_plan_compliance(
        self, 
        plan: ValidatedPlan, 
        policy_context: Optional[Dict[str, Any]]
    ) -> List[PolicyComplianceCheck]:
        """Check each plan step against policy rules."""
        checks = []
        context = policy_context or {}
        
        for step in plan.steps:
            # Determine relevant variables for this action type
            variables = self._extract_step_variables(step, context)
            
            # Check against each policy rule
            for rule in self.policy_set.rules:
                check = self._check_step_against_rule(step, rule, variables)
                if check:
                    checks.append(check)
        
        return checks
    
    def _extract_step_variables(
        self, 
        step: ValidatedStep, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract policy-relevant variables from a step."""
        variables = dict(context)
        
        # Add step-specific variables
        variables["action_type"] = step.action_type
        variables["resource"] = step.resource or ""
        variables["resource_type"] = step.resource_type
        variables["description"] = step.description
        
        # Add action-type specific variables
        if step.action_type in self.action_to_variables:
            for var_name in self.action_to_variables[step.action_type]:
                if var_name not in variables:
                    variables[var_name] = self._infer_variable(var_name, step, context)
        
        return variables
    
    def _infer_variable(
        self, 
        var_name: str, 
        step: ValidatedStep, 
        context: Dict[str, Any]
    ) -> Any:
        """Infer variable value from step and context."""
        # Default inferences
        if var_name == "user_consent":
            return context.get("user_consent", False)
        elif var_name == "requires_admin":
            # Check if action is admin-related
            if "admin" in step.description.lower() or "sudo" in (step.resource or "").lower():
                return True
            if step.action_type in ("shell_command", "shell_exec") and "admin" in step.description.lower():
                return True
            return False
        elif var_name == "risk_level":
            if "high" in step.description.lower() or "critical" in step.description.lower():
                return "high"
            if "admin" in step.description.lower() or "sudo" in (step.resource or "").lower():
                return "high"
            return "low"
        elif var_name == "command_type":
            if "admin" in step.description.lower() or "sudo" in (step.resource or "").lower():
                return "admin"
            return "user"
        elif var_name == "autonomy_level":
            return context.get("autonomy_level", 1)
        elif var_name == "path":
            # Extract path from resource
            return self._extract_path(step.resource, step.description) or step.resource or ""
        elif var_name == "resource_path":
            # Extract path from resource
            return self._extract_path(step.resource, step.description) or step.resource or ""
        elif var_name == "url":
            return step.resource or ""
        elif var_name == "data_sensitivity":
            if "personal" in step.description.lower() or "private" in step.description.lower():
                return "high"
            return "low"
        elif var_name == "query_type":
            if "update" in step.description.lower() or "delete" in step.description.lower():
                return "write"
            return "read"
        
        return context.get(var_name, "unknown")
    
    def _extract_path(self, resource: Optional[str], description: str = "") -> Optional[str]:
        """Extract file path from resource string or description."""
        # Try resource first
        for source in [resource, description]:
            if not source:
                continue
            # Common patterns: "to /etc/config", "file /tmp/old", "file ../../../etc/passwd"
            import re
            # Try to extract path-like patterns
            patterns = [
                r'(?:to|file|path)\s+(/[^\s]+)',
                r'(/[a-zA-Z0-9_\-./~]+)',  # Unix-like paths
            ]
            for pattern in patterns:
                match = re.search(pattern, source)
                if match:
                    return match.group(1)
        return None
    
    def _check_step_against_rule(
        self,
        step: ValidatedStep,
        rule: PolicyRule,
        variables: Dict[str, Any]
    ) -> Optional[PolicyComplianceCheck]:
        """Check a single step against a single policy rule."""
        try:
            # Evaluate rule condition against variables
            condition_result = self._evaluate_condition(rule.condition, variables)
            
            if not condition_result:
                # Condition not met - rule doesn't apply
                return None
            
            # Condition met - check action
            if rule.action == "deny":
                return PolicyComplianceCheck(
                    status=PolicyComplianceStatus.NON_COMPLIANT,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"Step '{step.id}' violates policy '{rule.id}': {rule.name}. Action denied.",
                    severity="critical",
                    suggested_action="Remove or modify step to comply with policy"
                )
            elif rule.action == "require_approval":
                return PolicyComplianceCheck(
                    status=PolicyComplianceStatus.REQUIRES_REVIEW,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"Step '{step.id}' requires approval per policy '{rule.id}': {rule.name}.",
                    severity="high",
                    suggested_action="Obtain user approval before executing"
                )
            elif rule.action == "allow":
                return PolicyComplianceCheck(
                    status=PolicyComplianceStatus.COMPLIANT,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"Step '{step.id}' allowed by policy '{rule.id}': {rule.name}.",
                    severity="low"
                )
        
        except Exception as e:
            logger.warning(f"Error checking rule {rule.id} against step {step.id}: {e}")
            return PolicyComplianceCheck(
                status=PolicyComplianceStatus.ERROR,
                rule_id=rule.id,
                rule_name=rule.name,
                message=f"Error evaluating policy: {e}",
                severity="medium"
            )
        
        return None
    
    def _evaluate_condition(
        self, 
        condition: Any, 
        variables: Dict[str, Any]
    ) -> bool:
        """Evaluate a policy condition against variable values.
        
        Handles both simple PolicyCondition and complex PolicyExpression
        with logical operators (AND, OR, IMPLIES, NOT, etc.)
        """
        from guardrail.formal_verification.policy_language import PolicyExpression, LogicalOperator
        
        # Handle simple PolicyCondition
        if isinstance(condition, PolicyCondition):
            var_value = variables.get(condition.variable)
            if var_value is None:
                return False
            return self._compare(var_value, condition.operator, condition.value)
        
        # Handle complex PolicyExpression with logical operators
        if isinstance(condition, PolicyExpression):
            if condition.operator == LogicalOperator.AND:
                return all(self._evaluate_condition(op, variables) for op in condition.operands)
            elif condition.operator == LogicalOperator.OR:
                return any(self._evaluate_condition(op, variables) for op in condition.operands)
            elif condition.operator == LogicalOperator.NOT:
                if condition.operands:
                    return not self._evaluate_condition(condition.operands[0], variables)
                return True
            elif condition.operator == LogicalOperator.IMPLIES:
                # For policy enforcement, IMPLIES is a conditional trigger:
                # "if antecedent is true, then consequent must be true"
                # For deny rules: if antecedent AND NOT consequent -> deny
                # So we check: antecedent is true AND consequent is false
                if len(condition.operands) >= 2:
                    antecedent = self._evaluate_condition(condition.operands[0], variables)
                    consequent = self._evaluate_condition(condition.operands[1], variables)
                    # Trigger (condition is "met" for enforcement) when antecedent true AND consequent false
                    return antecedent and (not consequent)
                return False
            elif condition.operator == LogicalOperator.IFF:
                if len(condition.operands) >= 2:
                    left = self._evaluate_condition(condition.operands[0], variables)
                    right = self._evaluate_condition(condition.operands[1], variables)
                    return left == right
                return True
            elif condition.operator in (LogicalOperator.FORALL, LogicalOperator.EXISTS):
                # Simplified handling - just evaluate first operand
                if condition.operands:
                    return self._evaluate_condition(condition.operands[0], variables)
                return True
        
        return False
    
    def _compare(self, left: Any, op: ComparisonOperator, right: Any) -> bool:
        """Compare two values using a comparison operator."""
        try:
            if op == ComparisonOperator.EQ:
                return left == right
            elif op == ComparisonOperator.NE:
                return left != right
            elif op == ComparisonOperator.LT:
                return left < right
            elif op == ComparisonOperator.LE:
                return left <= right
            elif op == ComparisonOperator.GT:
                return left > right
            elif op == ComparisonOperator.GE:
                return left >= right
            elif op == ComparisonOperator.IN:
                return left in right if isinstance(right, (list, set, tuple)) else False
            elif op == ComparisonOperator.NOT_IN:
                return left not in right if isinstance(right, (list, set, tuple)) else True
            elif op == ComparisonOperator.CONTAINS:
                return right in left if isinstance(left, (str, list, set, tuple)) else False
            elif op == ComparisonOperator.MATCHES:
                import re
                # For policy rules like safety_004, the pattern is \.\./.* 
                # which should match paths containing .. anywhere
                # Use search instead of match to find pattern anywhere in string
                pattern = str(right)
                text = str(left)
                # If pattern starts with ^ or $, use match, otherwise use search
                if pattern.startswith('^') or pattern.endswith('$'):
                    return bool(re.match(pattern, text))
                else:
                    return bool(re.search(pattern, text))
            elif op == ComparisonOperator.STARTS_WITH:
                return str(left).startswith(str(right))
            elif op == ComparisonOperator.ENDS_WITH:
                return str(left).endswith(str(right))
            elif op == ComparisonOperator.REGEX:
                import re
                return bool(re.search(str(right), str(left)))
        except Exception:
            return False
        return False
    
    def _has_policy_variables(
        self, 
        plan: ValidatedPlan, 
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Check if plan has variables that trigger policy verification."""
        for step in plan.steps:
            if step.action_type in self.action_to_variables:
                return True
        return False
    
    def _verify_plan_policies(
        self, 
        plan: ValidatedPlan, 
        context: Optional[Dict[str, Any]]
    ) -> VerificationReport:
        """Run formal verification on plan-relevant policies."""
        # Build context for verification
        all_variables = {}
        for step in plan.steps:
            step_vars = self._extract_step_variables(step, context or {})
            all_variables.update(step_vars)
        
        # Run verification
        return self.verifier.verify_policy_set(self.policy_set)
    
    def _generate_optimization_suggestions(
        self,
        plan: ValidatedPlan,
        compliance_checks: List[PolicyComplianceCheck],
        conflicts: List[PolicyConflict]
    ) -> List[str]:
        """Generate policy-aware optimization suggestions."""
        suggestions = []
        
        # Check for non-compliant steps that could be modified
        non_compliant = [c for c in compliance_checks 
                        if c.status == PolicyComplianceStatus.NON_COMPLIANT]
        if non_compliant:
            suggestions.append(
                f"Found {len(non_compliant)} non-compliant steps. "
                "Consider restructuring plan to avoid denied actions."
            )
        
        # Check for review-required steps
        requires_review = [c for c in compliance_checks 
                          if c.status == PolicyComplianceStatus.REQUIRES_REVIEW]
        if requires_review:
            suggestions.append(
                f"Found {len(requires_review)} steps requiring approval. "
                "Batch approval requests to minimize user interaction."
            )
        
        # Check for policy conflicts
        if conflicts:
            high_severity = [c for c in conflicts if c.severity in ("high", "critical")]
            if high_severity:
                suggestions.append(
                    f"Policy set has {len(high_severity)} high-severity conflicts. "
                    "Resolve policy conflicts before execution."
                )
        
        # Check for redundant steps
        action_types = [s.action_type for s in plan.steps]
        if len(action_types) != len(set(action_types)):
            suggestions.append(
                "Plan contains repeated action types. "
                "Consider consolidating similar operations."
            )
        
        return suggestions


def compile_policy_aware_plan(
    intent: str,
    plan_id: Optional[str] = None,
    agent_class: str = "coding",
    user_id: str = "user",
    autonomy_level: int = 1,
    policy_context: Optional[Dict[str, Any]] = None,
    policy_set: Optional[PolicySet] = None
) -> PolicyValidatedPlan:
    """Convenience function to compile a policy-aware plan.
    
    This is the main entry point for policy-aware plan compilation.
    """
    integration = PolicyIntegration(policy_set=policy_set)
    return integration.compile_policy_aware_plan(
        intent=intent,
        plan_id=plan_id,
        agent_class=agent_class,
        user_id=user_id,
        autonomy_level=autonomy_level,
        policy_context=policy_context
    )


# Policy-aware step validation (enhanced from existing)
def _validate_step_with_policy(
    step: ValidatedStep,
    policy_integration: PolicyIntegration,
    context: Dict[str, Any]
) -> ValidatedStep:
    """Enhanced step validation that includes policy checks."""
    # First run standard validation
    step = _validate_step_detailed(step)
    
    # Then check policy compliance
    variables = policy_integration._extract_step_variables(step, context)
    
    for rule in policy_integration.policy_set.rules:
        check = policy_integration._check_step_against_rule(step, rule, variables)
        if check and check.status == PolicyComplianceStatus.NON_COMPLIANT:
            step.validation_errors.append(f"Policy violation: {check.message}")
        elif check and check.status == PolicyComplianceStatus.REQUIRES_REVIEW:
            step.validation_errors.append(f"Requires approval: {check.message}")
    
    return step


if __name__ == "__main__":
    # Example usage
    example_intent = "Create a config file and run admin validation script"
    
    # Compile with default safety policies
    result = compile_policy_aware_plan(
        example_intent,
        plan_id="demo_001",
        agent_class="coding",
        user_id="user123",
        autonomy_level=2,
        policy_context={"user_consent": True}
    )
    
    print(f"Plan ID: {result.validated_plan.id}")
    print(f"Compliant: {result.is_compliant}")
    print(f"Critical Issues: {result.has_critical_issues}")
    print(f"Compliance Checks: {len(result.compliance_checks)}")
    
    for check in result.compliance_checks:
        print(f"  [{check.status.value}] {check.rule_id}: {check.message}")
    
    print(f"\nConflicts: {len(result.conflicts)}")
    for conflict in result.conflicts:
        print(f"  {conflict.conflict_type}: {conflict.rule1_id} vs {conflict.rule2_id}")
    
    print(f"\nOptimization Suggestions:")
    for s in result.optimization_suggestions:
        print(f"  - {s}")