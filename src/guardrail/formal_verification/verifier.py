"""SMT-based Deterministic Verifier for Guardrail (Z3 integration).

Provides formal verification of policy rules using the Z3 theorem prover.
Integrates with the symbolic policy language for sound verification.
"""
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from enum import Enum
from contextlib import contextmanager
import time
import hashlib

try:
    from z3 import (
        Solver, And, Or, Not, Implies, If, Bool, Int, Real, String,
        sat, unsat, unknown, simplify, substitute, Context,
        Function, DeclareSort, Const, ForAll, Exists,
        ModelRef, BoolVal, IntVal, RealVal, StringVal
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    # Mock classes for type hints when Z3 not available
    class Solver: pass
    class Context: pass
    class ModelRef: pass
    sat = unsat = unknown = None

from guardrail.formal_verification.policy_language import (
    PolicySet, PolicyRule, PolicyCondition, PolicyExpression,
    PolicyVariable, PolicyType, LogicalOperator, ComparisonOperator,
    create_safety_policy_set, create_resource_policy_set, create_compliance_policy_set,
)

logger = logging.getLogger(__name__)


class VerificationResult(Enum):
    """Result of a verification check."""
    SAT = "sat"           # Policy is satisfiable (no contradiction)
    UNSAT = "unsat"       # Policy is unsatisfiable (contradiction found)
    UNKNOWN = "unknown"   # Solver couldn't determine
    ERROR = "error"       # Error during verification
    TIMEOUT = "timeout"   # Verification timed out


@dataclass
class VerificationReport:
    """Report from a verification run."""
    result: VerificationResult
    policy_id: str
    rule_id: Optional[str] = None
    message: str = ""
    model: Optional[Dict[str, Any]] = None
    counterexample: Optional[Dict[str, Any]] = None
    execution_time_ms: float = 0.0
    smt_script: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class PolicyConflict:
    """Represents a conflict between policy rules."""
    rule1_id: str
    rule2_id: str
    conflict_type: str  # "direct", "indirect", "priority"
    description: str
    variables: Dict[str, Any]  # Variable assignment causing conflict
    severity: str = "medium"  # "low", "medium", "high", "critical"
    resolution_suggestion: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert conflict to dictionary for visualization."""
        return {
            "rule1_id": self.rule1_id,
            "rule2_id": self.rule2_id,
            "conflict_type": self.conflict_type,
            "description": self.description,
            "variables": self.variables,
            "severity": self.severity,
            "resolution_suggestion": self.resolution_suggestion,
        }
    
    def to_graph_node(self) -> Dict[str, str]:
        """Convert conflict to graph node representation."""
        return {
            "source": self.rule1_id,
            "target": self.rule2_id,
            "type": self.conflict_type,
            "label": f"{self.conflict_type}: {self.severity}",
        }


class Z3Verifier:
    """Z3-based formal verifier for Guardrail policies."""
    
    def __init__(self, timeout_ms: int = 5000):
        if not Z3_AVAILABLE:
            raise RuntimeError(
                "Z3 not available. Install with: pip install z3-solver"
            )
        self.timeout_ms = timeout_ms
        self.ctx = Context()
        self.solver = Solver(ctx=self.ctx)
        self.solver.set("timeout", timeout_ms)
        self._variable_map: Dict[str, Any] = {}  # name -> Z3 expression
        self._type_map: Dict[str, str] = {}      # name -> type
        self._verification_cache: Dict[str, VerificationReport] = {}  # Cache for verified policy sets
        self._variable_cache: Dict[str, Dict[str, Any]] = {}  # Cache for variable declarations
    
    def visualize_conflicts(self, policy_set: PolicySet, conflicts: List[PolicyConflict]) -> Dict[str, Any]:
        """Generate visualization data for conflicts."""
        nodes = []
        edges = []
        
        # Create nodes for each rule
        rule_ids = set()
        for conflict in conflicts:
            rule_ids.add(conflict.rule1_id)
            rule_ids.add(conflict.rule2_id)
        
        for rule_id in rule_ids:
            rule = next((r for r in policy_set.rules if r.id == rule_id), None)
            if rule:
                nodes.append({
                    "id": rule_id,
                    "label": rule.name,
                    "type": "rule",
                    "policy_type": rule.policy_type.value,
                    "priority": rule.priority,
                    "action": rule.action,
                })
        
        # Create edges for conflicts
        for conflict in conflicts:
            edges.append({
                "source": conflict.rule1_id,
                "target": conflict.rule2_id,
                "type": conflict.conflict_type,
                "severity": conflict.severity,
                "label": conflict.description[:50],
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "conflict_count": len(conflicts),
            "summary": {
                "direct": sum(1 for c in conflicts if c.conflict_type == "direct"),
                "indirect": sum(1 for c in conflicts if c.conflict_type == "indirect"),
                "priority": sum(1 for c in conflicts if c.conflict_type == "priority"),
            }
        }
    
    def generate_conflict_report(self, policy_set: PolicySet) -> str:
        """Generate a human-readable conflict report."""
        conflicts = self.check_rule_conflicts(policy_set)
        
        if not conflicts:
            return f"No conflicts found in policy set '{policy_set.name}'"
        
        lines = [
            f"Conflict Report for '{policy_set.name}' (v{policy_set.version})",
            f"=" * 60,
            f"Total conflicts: {len(conflicts)}",
            "",
        ]
        
        # Group by type
        by_type = {}
        for c in conflicts:
            by_type.setdefault(c.conflict_type, []).append(c)
        
        for conflict_type, conflict_list in by_type.items():
            lines.append(f"\n{conflict_type.upper()} CONFLICTS ({len(conflict_list)}):")
            lines.append("-" * 60)
            for c in conflict_list:
                lines.append(f"\n  Rules: {c.rule1_id} <-> {c.rule2_id}")
                lines.append(f"  Severity: {c.severity}")
                lines.append(f"  Description: {c.description}")
                if c.resolution_suggestion:
                    lines.append(f"  Suggestion: {c.resolution_suggestion}")
        
        return "\n".join(lines)
    
    def reset(self):
        """Reset the solver state."""
        self.solver = Solver(ctx=self.ctx)
        self.solver.set("timeout", self.timeout_ms)
        self._variable_map.clear()
        self._type_map.clear()
    
    def _get_policy_cache_key(self, policy_set: PolicySet) -> str:
        """Generate a cache key for a policy set based on its content."""
        import hashlib
        content = f"{policy_set.id}:{policy_set.version}:{len(policy_set.rules)}"
        for rule in sorted(policy_set.rules, key=lambda r: r.id):
            content += f":{rule.id}:{rule.priority}:{rule.action}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _declare_variable(self, var: PolicyVariable):
        """Declare a Z3 variable for a policy variable."""
        name = var.name
        if name in self._variable_map:
            return self._variable_map[name]
        
        if var.type == "string":
            z3_var = String(name, ctx=self.ctx)
        elif var.type == "int":
            z3_var = Int(name, ctx=self.ctx)
        elif var.type == "float":
            z3_var = Real(name, ctx=self.ctx)
        elif var.type == "bool":
            z3_var = Bool(name, ctx=self.ctx)
        else:
            # Default to string for unknown types
            z3_var = String(name, ctx=self.ctx)
        
        self._variable_map[name] = z3_var
        self._type_map[name] = var.type
        return z3_var
    
    def _condition_to_z3(self, condition: PolicyCondition) -> Any:
        """Convert a PolicyCondition to Z3 expression."""
        var = self._variable_map.get(condition.variable)
        if var is None:
            # Variable not declared - create it with inferred type
            inferred_type = self._infer_type(condition.value)
            var = self._declare_variable(PolicyVariable(condition.variable, inferred_type))
        
        val = condition.value
        op = condition.operator
        
        # Convert value to Z3 constant
        if isinstance(val, str):
            z3_val = StringVal(val, ctx=self.ctx)
        elif isinstance(val, bool):
            z3_val = BoolVal(val, ctx=self.ctx)
        elif isinstance(val, int):
            z3_val = IntVal(val, ctx=self.ctx)
        elif isinstance(val, float):
            z3_val = RealVal(val, ctx=self.ctx)
        else:
            z3_val = StringVal(str(val), ctx=self.ctx)
        
        if op == ComparisonOperator.EQ:
            return var == z3_val
        elif op == ComparisonOperator.NE:
            return var != z3_val
        elif op == ComparisonOperator.LT:
            return var < z3_val
        elif op == ComparisonOperator.LE:
            return var <= z3_val
        elif op == ComparisonOperator.GT:
            return var > z3_val
        elif op == ComparisonOperator.GE:
            return var >= z3_val
        elif op == ComparisonOperator.IN:
            return Or([var == self._to_z3_val(v) for v in val])
        elif op == ComparisonOperator.NOT_IN:
            return Not(Or([var == self._to_z3_val(v) for v in val]))
        elif op == ComparisonOperator.CONTAINS:
            # String contains - use Z3's Contains function
            from z3 import Contains
            return Contains(var, StringVal(val, ctx=self.ctx))
        elif op == ComparisonOperator.MATCHES:
            # Regex match - use Z3's Re and InRe with proper string pattern
            # Z3's Re expects a string literal for the regex pattern, not StringVal
            from z3 import Re, InRe, Contains
            # Use the pattern directly as string, Z3 will parse it as regex
            regex_pattern = str(val)
            try:
                # Try to create regex from pattern string
                regex = Re(regex_pattern)
                return InRe(var, regex)
            except:
                # Fallback: if regex parsing fails, use string contains as approximation
                logger.warning(f"Regex pattern '{regex_pattern}' could not be parsed, falling back to contains check")
                return Contains(var, StringVal(regex_pattern, ctx=self.ctx))
        elif op == ComparisonOperator.STARTS_WITH:
            from z3 import PrefixOf
            return PrefixOf(StringVal(val, ctx=self.ctx), var)
        elif op == ComparisonOperator.ENDS_WITH:
            from z3 import SuffixOf
            return SuffixOf(StringVal(val, ctx=self.ctx), var)
        elif op == ComparisonOperator.REGEX:
            from z3 import Re, InRe, Contains
            regex_pattern = str(val)
            try:
                regex = Re(regex_pattern)
                return InRe(var, regex)
            except:
                logger.warning(f"Regex pattern '{regex_pattern}' could not be parsed, falling back to contains check")
                return Contains(var, StringVal(regex_pattern, ctx=self.ctx))
        else:
            raise ValueError(f"Unknown operator: {op}")
    
    def _to_z3_val(self, val: Any) -> Any:
        """Convert Python value to Z3 constant."""
        if isinstance(val, str):
            return StringVal(val, ctx=self.ctx)
        elif isinstance(val, bool):
            return BoolVal(val, ctx=self.ctx)
        elif isinstance(val, int):
            return IntVal(val, ctx=self.ctx)
        elif isinstance(val, float):
            return RealVal(val, ctx=self.ctx)
        else:
            return StringVal(str(val), ctx=self.ctx)
    
    def _infer_type(self, value: Any) -> str:
        """Infer type from value."""
        if isinstance(value, bool):
            return "bool"
        elif isinstance(value, int):
            return "int"
        elif isinstance(value, float):
            return "float"
        else:
            return "string"
    
    def _expression_to_z3(self, expr: Union[PolicyExpression, PolicyCondition]) -> Any:
        """Convert a PolicyExpression to Z3 expression."""
        if isinstance(expr, PolicyCondition):
            return self._condition_to_z3(expr)
        
        op = expr.operator
        operands = [self._expression_to_z3(op) for op in expr.operands]
        
        if op == LogicalOperator.AND:
            return And(*operands)
        elif op == LogicalOperator.OR:
            return Or(*operands)
        elif op == LogicalOperator.NOT:
            assert len(operands) == 1
            return Not(operands[0])
        elif op == LogicalOperator.IMPLIES:
            assert len(operands) == 2
            return Implies(operands[0], operands[1])
        elif op == LogicalOperator.IFF:
            assert len(operands) == 2
            return operands[0] == operands[1]
        else:
            raise ValueError(f"Unknown operator: {op}")
    
    def verify_policy_set(self, policy_set: PolicySet) -> VerificationReport:
        """Verify an entire policy set for consistency with caching."""
        # Check cache first
        cache_key = self._get_policy_cache_key(policy_set)
        if cache_key in self._verification_cache:
            cached_report = self._verification_cache[cache_key]
            logger.info(f"Cache hit for policy set {policy_set.id}")
            # Return cached report with updated timing
            cached_report = VerificationReport(
                result=cached_report.result,
                policy_id=policy_set.id,
                rule_id=cached_report.rule_id,
                message=f"[CACHED] {cached_report.message}",
                model=cached_report.model,
                counterexample=cached_report.counterexample,
                execution_time_ms=0.0,  # Cached
                smt_script=cached_report.smt_script,
                errors=cached_report.errors,
                warnings=cached_report.warnings + ["Cached result"]
            )
            return cached_report
        
        start_time = time.time()
        self.reset()
        
        try:
            # Declare all variables
            for var in policy_set.get_all_variables():
                self._declare_variable(var)
            
            # Add all rules as assertions
            for rule in sorted(policy_set.rules, key=lambda r: -r.priority):
                z3_expr = self._rule_to_z3(rule)
                if z3_expr is not None:
                    self.solver.add(z3_expr)
            
            # Check satisfiability
            result = self.solver.check()
            elapsed = (time.time() - start_time) * 1000
            
            # Create report
            if result == sat:
                model = self.solver.model()
                model_dict = self._extract_model(model)
                report = VerificationReport(
                    result=VerificationResult.SAT,
                    policy_id=policy_set.id,
                    message="Policy set is consistent (satisfiable)",
                    model=model_dict,
                    execution_time_ms=elapsed,
                    smt_script=policy_set.to_smt_lib(),
                )
            elif result == unsat:
                report = VerificationReport(
                    result=VerificationResult.UNSAT,
                    policy_id=policy_set.id,
                    message="Policy set is inconsistent (unsatisfiable)",
                    execution_time_ms=elapsed,
                    smt_script=policy_set.to_smt_lib(),
                )
            elif result == unknown:
                report = VerificationReport(
                    result=VerificationResult.UNKNOWN,
                    policy_id=policy_set.id,
                    message="Solver could not determine (timeout or incomplete)",
                    execution_time_ms=elapsed,
                    smt_script=policy_set.to_smt_lib(),
                    warnings=["Solver timeout or unknown result"]
                )
            else:
                report = VerificationReport(
                    result=VerificationResult.ERROR,
                    policy_id=policy_set.id,
                    message=f"Unexpected solver result: {result}",
                    execution_time_ms=elapsed,
                    errors=[str(result)],
                )
            
            # Cache the result
            self._verification_cache[cache_key] = report
            return report
                
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            logger.error(f"Verification error: {e}")
            return VerificationReport(
                result=VerificationResult.ERROR,
                policy_id=policy_set.id,
                message=f"Verification failed: {e}",
                execution_time_ms=elapsed,
                errors=[str(e)],
            )
    
    def _rule_to_z3(self, rule: PolicyRule) -> Any:
        """Convert a PolicyRule to Z3 expression."""
        condition_z3 = self._expression_to_z3(rule.condition)
        
        if rule.precondition:
            precondition_z3 = self._expression_to_z3(rule.precondition)
            return Implies(precondition_z3, condition_z3)
        else:
            return condition_z3
    
    def _extract_model(self, model: ModelRef) -> Dict[str, Any]:
        """Extract values from Z3 model."""
        result = {}
        for decl in model.decls():
            name = decl.name()
            value = model[decl]
            try:
                if value is not None:
                    result[name] = value.as_string() if hasattr(value, 'as_string') else str(value)
            except:
                result[name] = str(value)
        return result
    
    def check_rule_conflicts(self, policy_set: PolicySet) -> List[PolicyConflict]:
        """Check for conflicts between rules in a policy set."""
        conflicts = []
        
        # Direct pairwise conflicts
        for i, rule1 in enumerate(policy_set.rules):
            for rule2 in policy_set.rules[i+1:]:
                conflict = self._check_pair_conflict(rule1, rule2)
                if conflict:
                    conflicts.append(conflict)
        
        # Indirect conflicts via intermediate rules
        indirect_conflicts = self._check_indirect_conflicts(policy_set)
        conflicts.extend(indirect_conflicts)
        
        return conflicts
    
    def _check_indirect_conflicts(self, policy_set: PolicySet) -> List[PolicyConflict]:
        """Check for indirect conflicts through chains of rules."""
        conflicts = []
        rules = policy_set.rules
        
        # Check for conflicts where rule1 -> rule2 -> rule3 creates indirect conflict
        for i, rule1 in enumerate(rules):
            for j, rule2 in enumerate(rules):
                if i == j:
                    continue
                for k, rule3 in enumerate(rules):
                    if k == i or k == j:
                        continue
                    
                    # Check if rule1 and rule3 conflict indirectly through rule2
                    indirect = self._check_indirect_triple(rule1, rule2, rule3)
                    if indirect:
                        conflicts.append(indirect)
        
        return conflicts
    
    def _check_indirect_triple(self, rule1: PolicyRule, rule2: PolicyRule, rule3: PolicyRule) -> Optional[PolicyConflict]:
        """Check if three rules create an indirect conflict."""
        self.reset()
        
        # Get all variables
        all_vars = {}
        for rule in [rule1, rule2, rule3]:
            for var in rule.variables:
                if var.name not in all_vars:
                    all_vars[var.name] = var
        
        for var in all_vars.values():
            self._declare_variable(var)
        
        # Add rule1 and rule3
        z3_1 = self._rule_to_z3(rule1)
        z3_3 = self._rule_to_z3(rule3)
        
        if z3_1 is not None:
            self.solver.add(z3_1)
        if z3_3 is not None:
            self.solver.add(z3_3)
        
        # Check if they can both be true, but rule2 makes them mutually exclusive
        self.solver.push()
        z3_2 = self._rule_to_z3(rule2)
        if z3_2 is not None:
            self.solver.add(z3_2)
        
        result = self.solver.check()
        self.solver.pop()
        
        if result == unsat:
            # Check if rule1 and rule3 are individually satisfiable
            self.solver.push()
            self.solver.add(z3_1)
            result1 = self.solver.check()
            self.solver.pop()
            
            self.solver.push()
            self.solver.add(z3_3)
            result3 = self.solver.check()
            self.solver.pop()
            
            if result1 == sat and result3 == sat:
                # Indirect conflict: rule1 and rule3 are fine alone, but conflict with rule2
                return PolicyConflict(
                    rule1_id=rule1.id,
                    rule2_id=rule3.id,
                    conflict_type="indirect",
                    description=f"Rules {rule1.name} and {rule3.name} conflict indirectly via {rule2.name}",
                    variables={},
                )
        
        return None
    
    def _check_pair_conflict(self, rule1: PolicyRule, rule2: PolicyRule) -> Optional[PolicyConflict]:
        """Check if two rules conflict."""
        self.reset()
        
        # Declare variables from both rules
        all_vars = {}
        for rule in [rule1, rule2]:
            for var in rule.variables:
                if var.name not in all_vars:
                    all_vars[var.name] = var
        
        for var in all_vars.values():
            self._declare_variable(var)
        
        # Add both rules
        z3_1 = self._rule_to_z3(rule1)
        z3_2 = self._rule_to_z3(rule2)
        
        if z3_1 is not None:
            self.solver.add(z3_1)
        if z3_2 is not None:
            self.solver.add(z3_2)
        
        # Check if they can both be true
        result = self.solver.check()
        
        if result == unsat:
            # Direct conflict - they cannot both be satisfied
            severity = self._calculate_conflict_severity(rule1, rule2, "direct")
            suggestion = self._suggest_resolution(rule1, rule2, "direct")
            
            return PolicyConflict(
                rule1_id=rule1.id,
                rule2_id=rule2.id,
                conflict_type="direct",
                description=f"Rules {rule1.name} and {rule2.name} are mutually exclusive",
                variables={},
                severity=severity,
                resolution_suggestion=suggestion,
            )
        elif result == sat:
            # Check if they have opposite actions on overlapping conditions
            model = self.solver.model()
            model_dict = self._extract_model(model)
            
            if rule1.action == "deny" and rule2.action == "allow":
                severity = self._calculate_conflict_severity(rule1, rule2, "priority")
                suggestion = self._suggest_resolution(rule1, rule2, "priority")
                
                return PolicyConflict(
                    rule1_id=rule1.id,
                    rule2_id=rule2.id,
                    conflict_type="priority",
                    description=f"Rule {rule1.name} denies what {rule2.name} allows",
                    variables=model_dict,
                    severity=severity,
                    resolution_suggestion=suggestion,
                )
        
        return None
    
    def _calculate_conflict_severity(self, rule1: PolicyRule, rule2: PolicyRule, conflict_type: str) -> str:
        """Calculate severity of a conflict."""
        # Higher priority rules = higher severity
        max_priority = max(rule1.priority, rule2.priority)
        
        # Critical policy types
        critical_types = ["safety", "security", "compliance"]
        is_critical = (rule1.policy_type.value in critical_types or 
                      rule2.policy_type.value in critical_types)
        
        # Direct conflicts are more severe
        if conflict_type == "direct":
            if is_critical and max_priority >= 100:
                return "critical"
            elif is_critical or max_priority >= 50:
                return "high"
            else:
                return "medium"
        elif conflict_type == "priority":
            if max_priority >= 100:
                return "high"
            else:
                return "medium"
        elif conflict_type == "indirect":
            return "low"
        else:
            return "medium"
    
    def _suggest_resolution(self, rule1: PolicyRule, rule2: PolicyRule, conflict_type: str) -> str:
        """Suggest resolution for a conflict."""
        if conflict_type == "direct":
            if rule1.priority > rule2.priority:
                return f"Consider removing or relaxing {rule2.name} (lower priority)"
            elif rule2.priority > rule1.priority:
                return f"Consider removing or relaxing {rule1.name} (lower priority)"
            else:
                return f"Consider merging conditions or adjusting priority for {rule1.name} and {rule2.name}"
        elif conflict_type == "priority":
            if rule1.priority > rule2.priority:
                return f"Rule {rule1.name} takes precedence (higher priority)"
            elif rule2.priority > rule1.priority:
                return f"Rule {rule2.name} takes precedence (higher priority)"
            else:
                return f"Consider adjusting priority or making one rule more specific"
        elif conflict_type == "indirect":
            return f"Review intermediate rules that create indirect conflict"
        else:
            return "Manual review required"
    
    def resolve_conflict(self, conflict: PolicyConflict, strategy: str = "priority") -> Dict[str, Any]:
        """Attempt to resolve a conflict using a strategy."""
        strategies = {
            "priority": self._resolve_by_priority,
            "specificity": self._resolve_by_specificity,
            "merge": self._resolve_by_merge,
        }
        
        resolver = strategies.get(strategy, self._resolve_by_priority)
        return resolver(conflict)
    
    def _resolve_by_priority(self, conflict: PolicyConflict) -> Dict[str, Any]:
        """Resolve by keeping higher priority rule."""
        return {
            "strategy": "priority",
            "resolution": "Keep higher priority rule, modify lower priority rule",
            "conflict_id": f"{conflict.rule1_id}-{conflict.rule2_id}",
        }
    
    def _resolve_by_specificity(self, conflict: PolicyConflict) -> Dict[str, Any]:
        """Resolve by keeping more specific rule."""
        return {
            "strategy": "specificity",
            "resolution": "Keep more specific rule (narrower conditions)",
            "conflict_id": f"{conflict.rule1_id}-{conflict.rule2_id}",
        }
    
    def _resolve_by_merge(self, conflict: PolicyConflict) -> Dict[str, Any]:
        """Resolve by merging rules."""
        return {
            "strategy": "merge",
            "resolution": "Merge rules into single rule with combined conditions",
            "conflict_id": f"{conflict.rule1_id}-{conflict.rule2_id}",
        }
    
    def verify_action(
        self,
        policy_set: PolicySet,
        action_vars: Dict[str, Any],
    ) -> Tuple[bool, Optional[str], List[str]]:
        """Verify if a specific action is allowed under the policy set.
        
        Returns: (allowed, reason, applicable_rules)
        """
        self.reset()
        
        # Declare all variables
        for var in policy_set.get_all_variables():
            self._declare_variable(var)
        
        # Add all rules
        for rule in sorted(policy_set.rules, key=lambda r: -r.priority):
            z3_expr = self._rule_to_z3(rule)
            if z3_expr is not None:
                self.solver.add(z3_expr)
        
        # Add action variables as constraints
        for name, value in action_vars.items():
            var = self._variable_map.get(name)
            if var is not None:
                z3_val = self._to_z3_val(value)
                self.solver.add(var == z3_val)
        
        # Check if policy + action is satisfiable
        result = self.solver.check()
        
        if result == unsat:
            # Policy violated - find which rule(s)
            violating_rules = self._find_violating_rules(policy_set, action_vars)
            if violating_rules:
                rule_ids = [r.id for r in violating_rules]
                reasons = [f"Violates {r.name} ({r.id})" for r in violating_rules]
                return False, "; ".join(reasons), rule_ids
            return False, "Policy violated (unsatisfiable)", []
        
        # Check for require_approval rules that are triggered
        approval_rules = [r for r in policy_set.rules if r.action == "require_approval"]
        triggered_approvals = []
        for rule in approval_rules:
            self.solver.push()
            if rule.precondition:
                self.solver.add(self._expression_to_z3(rule.precondition))
            self.solver.add(self._expression_to_z3(rule.condition))
            result = self.solver.check()
            self.solver.pop()
            
            if result == sat:
                triggered_approvals.append(rule)
        
        if triggered_approvals:
            rule_ids = [r.id for r in triggered_approvals]
            reasons = [f"Requires approval: {r.name} ({r.id})" for r in triggered_approvals]
            return True, "; ".join(reasons), rule_ids
        
        return True, "Allowed", []
    
    def _find_violating_rules(self, policy_set: PolicySet, action_vars: Dict[str, Any]) -> List[PolicyRule]:
        """Find which rules are violated by the action."""
        violating = []
        
        for rule in policy_set.rules:
            self.solver.push()
            
            # Add action vars
            for name, value in action_vars.items():
                var = self._variable_map.get(name)
                if var is not None:
                    z3_val = self._to_z3_val(value)
                    self.solver.add(var == z3_val)
            
            # Check if this rule's condition is violated
            # A rule is violated if: precondition is true AND condition is false
            if rule.precondition:
                self.solver.add(self._expression_to_z3(rule.precondition))
            
            z3_cond = self._expression_to_z3(rule.condition)
            self.solver.add(Not(z3_cond))
            
            result = self.solver.check()
            self.solver.pop()
            
            if result == sat:
                # This rule can be violated - check if it's a deny/require_approval rule
                if rule.action in ["deny", "require_approval"]:
                    violating.append(rule)
        
        return violating
    
    @contextmanager
    def temporary_assertion(self, expr: Any):
        """Context manager for temporary assertions."""
        self.solver.push()
        self.solver.add(expr)
        try:
            yield
        finally:
            self.solver.pop()


class MockVerifier:
    """Mock verifier for when Z3 is not available."""
    
    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms
        logger.warning("Using MockVerifier - Z3 not available")
    
    def reset(self):
        pass
    
    def verify_policy_set(self, policy_set: PolicySet) -> VerificationReport:
        return VerificationReport(
            result=VerificationResult.SAT,
            policy_id=policy_set.id,
            message="Mock verification: assuming consistent (Z3 not installed)",
            execution_time_ms=1.0,
            warnings=["Z3 not installed - using mock verifier"],
        )
    
    def check_rule_conflicts(self, policy_set: PolicySet) -> List[PolicyConflict]:
        return []
    
    def verify_action(
        self,
        policy_set: PolicySet,
        action_vars: Dict[str, Any],
    ) -> Tuple[bool, Optional[str], List[str]]:
        # Simple mock logic based on action type and autonomy level
        action_type = action_vars.get("action_type", "")
        autonomy_level = action_vars.get("autonomy_level", 0)
        user_consent = action_vars.get("user_consent", False)
        requires_admin = action_vars.get("requires_admin", False)
        
        if requires_admin and not user_consent:
            return False, "Admin action requires user consent", ["safety_001"]
        
        if action_type == "file_read" and autonomy_level >= 0:
            return True, "Allowed", []
        elif action_type == "file_write" and autonomy_level >= 1:
            return True, "Allowed", []
        elif action_type == "shell_command" and autonomy_level >= 2:
            return True, "Allowed", []
        elif action_type in ["system_modify", "network_config"] and autonomy_level >= 3:
            return True, "Allowed", []
        elif action_type in ["file_write", "shell_command", "system_modify", "network_config"]:
            return False, f"Insufficient autonomy level for {action_type}", ["safety_003"]
        
        return True, "Allowed (mock)", []


def create_verifier(timeout_ms: int = 5000):
    """Factory function to create appropriate verifier."""
    if Z3_AVAILABLE:
        return Z3Verifier(timeout_ms)
    else:
        return MockVerifier(timeout_ms)


# ----------------------------------------------------------------------
# Verification Pipeline
# ----------------------------------------------------------------------

@dataclass
class VerificationPipeline:
    """Pipeline for running multiple verification checks."""
    verifier: Any  # Z3Verifier or MockVerifier
    policy_sets: List[PolicySet] = field(default_factory=list)
    
    def add_policy_set(self, policy_set: PolicySet):
        self.policy_sets.append(policy_set)
    
    def run_all(self) -> Dict[str, VerificationReport]:
        """Run verification on all policy sets."""
        results = {}
        for ps in self.policy_sets:
            results[ps.id] = self.verifier.verify_policy_set(ps)
        return results
    
    def check_all_conflicts(self) -> Dict[str, List[PolicyConflict]]:
        """Check conflicts in all policy sets."""
        results = {}
        for ps in self.policy_sets:
            results[ps.id] = self.verifier.check_rule_conflicts(ps)
        return results
    
    def verify_action_across_sets(
        self,
        action_vars: Dict[str, Any],
    ) -> Tuple[bool, List[str], List[str]]:
        """Verify action against all policy sets.
        
        Returns: (allowed, reasons, applicable_rule_ids)
        """
        all_allowed = True
        all_reasons = []
        all_rules = []
        
        for ps in self.policy_sets:
            allowed, reason, rules = self.verifier.verify_action(ps, action_vars)
            if not allowed:
                all_allowed = False
            all_reasons.append(f"[{ps.name}] {reason}")
            all_rules.extend(rules)
        
        return all_allowed, all_reasons, all_rules


# ----------------------------------------------------------------------
# Example Usage
# ----------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create verifier
    verifier = create_verifier()
    
    # Create policy sets
    safety = create_safety_policy_set()
    resource = create_resource_policy_set()
    compliance = create_compliance_policy_set()
    
    print("=== Verifying Safety Policy Set ===")
    report = verifier.verify_policy_set(safety)
    print(f"Result: {report.result.value}")
    print(f"Message: {report.message}")
    print(f"Time: {report.execution_time_ms:.2f}ms")
    if report.model:
        print(f"Model: {report.model}")
    
    print("\n=== Checking Conflicts ===")
    conflicts = verifier.check_rule_conflicts(safety)
    for c in conflicts:
        print(f"Conflict: {c.rule1_id} vs {c.rule2_id} ({c.conflict_type})")
        print(f"  {c.description}")
    
    print("\n=== Verifying Actions ===")
    test_actions = [
        {"action_type": "file_read", "autonomy_level": 0, "user_consent": False, "requires_admin": False},
        {"action_type": "file_write", "autonomy_level": 0, "user_consent": False, "requires_admin": False},
        {"action_type": "file_write", "autonomy_level": 1, "user_consent": False, "requires_admin": False},
        {"action_type": "shell_command", "autonomy_level": 2, "user_consent": False, "requires_admin": False},
        {"action_type": "file_delete", "autonomy_level": 3, "user_consent": True, "requires_admin": True},
        {"action_type": "file_delete", "autonomy_level": 3, "user_consent": False, "requires_admin": True},
    ]
    
    for action in test_actions:
        allowed, reason, rules = verifier.verify_action(safety, action)
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        print(f"  {status}: {action['action_type']} @ L{action.get('autonomy_level', '?')} - {reason}")
    
    print("\n=== Pipeline Verification ===")
    pipeline = VerificationPipeline(verifier)
    pipeline.add_policy_set(safety)
    pipeline.add_policy_set(resource)
    pipeline.add_policy_set(compliance)
    
    all_results = pipeline.run_all()
    for pid, report in all_results.items():
        print(f"  {pid}: {report.result.value} - {report.message}")
    
    # Test action across all policies
    action = {"action_type": "file_write", "autonomy_level": 1, "user_consent": False, "requires_admin": False,
              "cpu_usage": 50.0, "memory_mb": 512, "network_mbps": 10.0, "execution_time_s": 60,
              "is_high_risk_ai": False}
    
    allowed, reasons, rules = pipeline.verify_action_across_sets(action)
    print(f"\nCross-policy check for file_write @ L1:")
    print(f"  Allowed: {allowed}")
    for r in reasons:
        print(f"  - {r}")