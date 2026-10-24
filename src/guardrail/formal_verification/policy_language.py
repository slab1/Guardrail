"""Symbolic Policy Language for Guardrail (VEPA-style).

Provides a typed, declarative language for expressing formal policies
that can be verified by an SMT solver.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Union
from enum import Enum
from abc import ABC, abstractmethod
import hashlib
import json

class PolicyType(Enum):
    """Types of policies in the system."""
    SAFETY = "safety"           # Prevents harmful actions
    SECURITY = "security"       # Access control, auth
    RESOURCE = "resource"       # Resource limits, quotas
    COMPLIANCE = "compliance"   # Regulatory requirements
    OPERATIONAL = "operational" # Workflow constraints


class LogicalOperator(Enum):
    """Logical operators for policy composition."""
    AND = "and"
    OR = "or"
    NOT = "not"
    IMPLIES = "implies"
    IFF = "iff"
    FORALL = "forall"  # Universal quantification
    EXISTS = "exists"  # Existential quantification


class TemporalOperator(Enum):
    """Temporal logic operators for time-based policies."""
    ALWAYS = "always"  # □ - always in future
    EVENTUALLY = "eventually"  # ◇ - eventually in future
    UNTIL = "until"  # U - until
    NEXT = "next"  # X - next state
    PREVIOUS = "previous"  # Y - previous state
    SINCE = "since"  # S - since


class ComparisonOperator(Enum):
    """Comparison operators for conditions."""
    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    MATCHES = "matches"  # regex
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"  # Full regex support


@dataclass(frozen=True)
class PolicyVariable:
    """A typed variable in a policy expression."""
    name: str
    type: str  # "string", "int", "float", "bool", "list", "dict"
    description: str = ""
    
    def __str__(self) -> str:
        return f"{self.name}: {self.type}"


@dataclass(frozen=True)
class PolicyCondition:
    """A single condition in a policy rule."""
    variable: str
    operator: ComparisonOperator
    value: Any
    description: str = ""
    
    def to_smt(self) -> str:
        """Convert to SMT-LIB format."""
        var = self.variable
        op = self.operator
        val = self.value
        
        if op == ComparisonOperator.EQ:
            return f"(= {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.NE:
            return f"(not (= {var} {self._smt_value(val)}))"
        elif op == ComparisonOperator.LT:
            return f"(< {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.LE:
            return f"(<= {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.GT:
            return f"(> {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.GE:
            return f"(>= {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.IN:
            return f"(or {' '.join(f'(= {var} {self._smt_value(v)})' for v in val)})"
        elif op == ComparisonOperator.NOT_IN:
            return f"(not (or {' '.join(f'(= {var} {self._smt_value(v)})' for v in val)}))"
        elif op == ComparisonOperator.CONTAINS:
            return f"(str.contains {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.MATCHES:
            return f"(str.match {var} {self._smt_value(val)})"
        elif op == ComparisonOperator.STARTS_WITH:
            return f"(str.prefixof {self._smt_value(val)} {var})"
        elif op == ComparisonOperator.ENDS_WITH:
            return f"(str.suffixof {self._smt_value(val)} {var})"
        elif op == ComparisonOperator.REGEX:
            return f"(str.in_re {var} (re.++ {self._smt_value(val)}))"
        else:
            raise ValueError(f"Unknown operator: {op}")
    
    def _smt_value(self, v: Any) -> str:
        if isinstance(v, str):
            return f'"{v}"'
        elif isinstance(v, bool):
            return "true" if v else "false"
        elif isinstance(v, (int, float)):
            return str(v)
        else:
            return f'"{json.dumps(v)}"'


@dataclass(frozen=True)
class TemporalPolicyCondition:
    """A temporal condition using temporal logic operators."""
    operator: TemporalOperator
    operand: Union["PolicyExpression", PolicyCondition]
    duration: Optional[int] = None  # Optional duration in seconds
    
    def to_smt(self) -> str:
        """Convert to SMT-LIB format with temporal comment."""
        operand_smt = self.operand.to_smt()
        temporal_comment = ""
        if self.duration:
            temporal_comment = f"; Temporal: {self.operator.value} for {self.duration}s"
        
        # Temporal operators are annotations in SMT-LIB since it's atemporal
        # We use comments to indicate temporal constraints
        if self.operator == TemporalOperator.ALWAYS:
            return f";; ALWAYS: {operand_smt} {temporal_comment}"
        elif self.operator == TemporalOperator.EVENTUALLY:
            return f";; EVENTUALLY: {operand_smt} {temporal_comment}"
        elif self.operator == TemporalOperator.NEXT:
            return f";; NEXT: {operand_smt} {temporal_comment}"
        elif self.operator == TemporalOperator.UNTIL:
            return f";; UNTIL: {operand_smt} {temporal_comment}"
        else:
            return f";; TEMPORAL: {operand_smt} {temporal_comment}"


@dataclass(frozen=True)
class PolicyExpression:
    """A logical expression combining conditions."""
    operator: LogicalOperator
    operands: List[Union["PolicyExpression", PolicyCondition, TemporalPolicyCondition]]
    
    def to_smt(self) -> str:
        """Convert to SMT-LIB format."""
        if self.operator == LogicalOperator.NOT:
            assert len(self.operands) == 1
            return f"(not {self.operands[0].to_smt()})"
        else:
            ops = " ".join(op.to_smt() for op in self.operands)
            if self.operator == LogicalOperator.AND:
                return f"(and {ops})"
            elif self.operator == LogicalOperator.OR:
                return f"(or {ops})"
            elif self.operator == LogicalOperator.IMPLIES:
                assert len(self.operands) == 2
                return f"(=> {self.operands[0].to_smt()} {self.operands[1].to_smt()})"
            elif self.operator == LogicalOperator.IFF:
                assert len(self.operands) == 2
                return f"(= {self.operands[0].to_smt()} {self.operands[1].to_smt()})"
            elif self.operator == LogicalOperator.FORALL:
                return f"(forall ((var Int)) {ops})"
            elif self.operator == LogicalOperator.EXISTS:
                return f"(exists ((var Int)) {ops})"
            else:
                raise ValueError(f"Unknown operator: {self.operator}")


@dataclass
class PolicyRule:
    """A single policy rule with conditions and actions."""
    id: str
    name: str
    policy_type: PolicyType
    description: str
    variables: List[PolicyVariable]
    precondition: Optional[Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]]
    condition: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]
    action: str
    priority: int = 0
    evidence_required: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            content = f"{self.name}:{self.condition}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_smt(self, prefix: str = "") -> str:
        """Convert rule to SMT-LIB assertions."""
        cond_smt = self._to_smt(self.condition)
        if self.precondition:
            pre_smt = self._to_smt(self.precondition)
            return f"(assert (=> {pre_smt} {cond_smt}))"
        else:
            return f"(assert {cond_smt})"
    
    def _to_smt(self, expr: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]) -> str:
        """Convert expression or condition to SMT."""
        return expr.to_smt()
    
    def get_variables_declaration(self) -> List[str]:
        """Get SMT declarations for all variables."""
        decls = []
        for var in self.variables:
            smt_type = self._type_to_smt(var.type)
            decls.append(f"(declare-const {var.name} {smt_type})")
        return decls
    
    def _type_to_smt(self, t: str) -> str:
        mapping = {
            "string": "String",
            "int": "Int",
            "float": "Real",
            "bool": "Bool",
            "list": "Array",
            "dict": "Array",
        }
        return mapping.get(t, "String")


@dataclass
class PolicySet:
    """A collection of policy rules forming a complete policy."""
    id: str
    name: str
    version: str
    rules: List[PolicyRule]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(self.name.encode()).hexdigest()[:16]
    
    def get_all_variables(self) -> List[PolicyVariable]:
        """Get all unique variables across rules."""
        seen = set()
        result = []
        for rule in self.rules:
            for var in rule.variables:
                if var.name not in seen:
                    seen.add(var.name)
                    result.append(var)
        return result
    
    def _variable_to_smt(self, var: 'PolicyVariable') -> str:
        """Convert a variable to SMT-LIB declaration."""
        smt_type = self._type_to_smt(var.type)
        return f"(declare-const {var.name} {smt_type})"
    
    def _type_to_smt(self, t: str) -> str:
        mapping = {
            "string": "String",
            "int": "Int",
            "float": "Real",
            "bool": "Bool",
            "list": "Array",
            "dict": "Array",
        }
        return mapping.get(t, "String")
    
    def to_smt_lib(self) -> str:
        """Export entire policy set as SMT-LIB script."""
        lines = [
            "(set-logic ALL)",
            "; Policy set: " + self.name,
            f"; Version: {self.version}",
            f"; ID: {self.id}",
            "",
        ]
        
        for var in self.get_all_variables():
            decl = self._variable_to_smt(var)
            lines.append(decl)
        
        lines.append("")
        
        for rule in sorted(self.rules, key=lambda r: -r.priority):
            lines.append(f"; Rule: {rule.name} ({rule.id})")
            lines.append(rule.to_smt())
            lines.append("")
        
        lines.append("(check-sat)")
        lines.append("(get-model)")
        
        return "\n".join(lines)


def create_safety_policy_set() -> PolicySet:
    """Create a standard safety policy set."""
    
    action_type = PolicyVariable("action_type", "string", "Type of action being performed")
    resource_path = PolicyVariable("resource_path", "string", "Path to resource")
    autonomy_level = PolicyVariable("autonomy_level", "int", "Agent autonomy level (0-3)")
    user_consent = PolicyVariable("user_consent", "bool", "Whether user has given consent")
    risk_level = PolicyVariable("risk_level", "string", "Risk level of action")
    requires_admin = PolicyVariable("requires_admin", "bool", "Whether action requires admin")
    action_taken = PolicyVariable("action_taken", "string", "Action performed")
    
    rules = [
        PolicyRule(
            id="safety_001",
            name="Block Admin Actions Without Consent",
            policy_type=PolicyType.SAFETY,
            description="Admin actions require explicit user consent",
            variables=[action_type, requires_admin, user_consent],
            precondition=PolicyExpression(
                LogicalOperator.AND,
                [
                    PolicyCondition("requires_admin", ComparisonOperator.EQ, True),
                    PolicyCondition("action_type", ComparisonOperator.IN, ["file_delete", "system_modify", "network_config"]),
                ]
            ),
            condition=PolicyExpression(
                LogicalOperator.IMPLIES,
                [
                    PolicyCondition("requires_admin", ComparisonOperator.EQ, True),
                    PolicyCondition("user_consent", ComparisonOperator.EQ, True),
                ]
            ),
            action="deny",
            priority=100,
            evidence_required=["user_consent_record"],
        ),
        PolicyRule(
            id="safety_002",
            name="High Risk Actions Require Approval",
            policy_type=PolicyType.SAFETY,
            description="High risk actions need approval",
            variables=[risk_level, user_consent],
            precondition=None,
            condition=PolicyExpression(
                LogicalOperator.IMPLIES,
                [
                    PolicyCondition("risk_level", ComparisonOperator.EQ, "high"),
                    PolicyCondition("user_consent", ComparisonOperator.EQ, True),
                ]
            ),
            action="deny",
            priority=90,
            evidence_required=["approval_record"],
        ),
        PolicyRule(
            id="safety_003",
            name="Autonomy Level Enforcement",
            policy_type=PolicyType.SAFETY,
            description="Enforce autonomy level constraints",
            variables=[autonomy_level, action_type],
            precondition=None,
            condition=PolicyExpression(
                LogicalOperator.AND,
                [
                    PolicyCondition("autonomy_level", ComparisonOperator.LE, 1),
                    PolicyCondition("action_type", ComparisonOperator.IN, ["file_delete", "system_modify"]),
                ]
            ),
            action="deny",
            priority=80,
        ),
        PolicyRule(
            id="safety_004",
            name="Path Traversal Prevention",
            policy_type=PolicyType.SAFETY,
            description="Prevent path traversal attacks",
            variables=[resource_path],
            precondition=None,
            condition=PolicyCondition("resource_path", ComparisonOperator.MATCHES, r"\.\./.*"),
            action="deny",
            priority=95,
        ),
        PolicyRule(
            id="safety_005",
            name="Sensitive Path Protection",
            policy_type=PolicyType.SAFETY,
            description="Protect sensitive paths",
            variables=[resource_path],
            precondition=None,
            condition=PolicyCondition("resource_path", ComparisonOperator.STARTS_WITH, "/etc/"),
            action="deny",
            priority=85,
        ),
    ]
    
    return PolicySet(
        id="guardrail_safety_v1",
        name="Guardrail Safety Policy Set v1",
        version="1.0.0",
        rules=rules,
    )


def create_resource_policy_set() -> PolicySet:
    """Create resource management policies."""
    
    resource_type = PolicyVariable("resource_type", "string", "Type of resource")
    resource_size = PolicyVariable("resource_size", "int", "Size of resource in MB")
    autonomy_level = PolicyVariable("autonomy_level", "int", "Agent autonomy level")
    user_approval = PolicyVariable("user_approval", "bool", "User approval obtained")
    cpu_usage = PolicyVariable("cpu_usage", "int", "CPU usage percentage")
    memory_usage = PolicyVariable("memory_usage", "int", "Memory usage MB")
    network_bytes = PolicyVariable("network_bytes", "int", "Network bytes per second")
    execution_time = PolicyVariable("execution_time", "int", "Execution time seconds")
    
    rules = [
        PolicyRule(
            id="resource_001",
            name="CPU Limit",
            policy_type=PolicyType.RESOURCE,
            description="Limit CPU usage",
            variables=[cpu_usage],
            precondition=None,
            condition=PolicyCondition("cpu_usage", ComparisonOperator.LE, 80),
            action="deny",
            priority=70,
        ),
        PolicyRule(
            id="resource_002",
            name="Memory Limit",
            policy_type=PolicyType.RESOURCE,
            description="Limit memory usage",
            variables=[memory_usage],
            precondition=None,
            condition=PolicyCondition("memory_usage", ComparisonOperator.LE, 1024),
            action="deny",
            priority=70,
        ),
        PolicyRule(
            id="resource_003",
            name="Network Rate Limit",
            policy_type=PolicyType.RESOURCE,
            description="Limit network bandwidth",
            variables=[network_bytes],
            precondition=None,
            condition=PolicyCondition("network_bytes", ComparisonOperator.LE, 1000000),
            action="deny",
            priority=60,
        ),
        PolicyRule(
            id="resource_004",
            name="Execution Timeout",
            policy_type=PolicyType.RESOURCE,
            description="Limit execution time",
            variables=[execution_time],
            precondition=None,
            condition=PolicyCondition("execution_time", ComparisonOperator.LE, 300),
            action="deny",
            priority=65,
        ),
    ]
    
    return PolicySet(
        id="guardrail_resource_v1",
        name="Guardrail Resource Policy Set v1",
        version="1.0.0",
        rules=rules,
    )


def create_compliance_policy_set() -> PolicySet:
    """Create compliance policies (AI Act, NIST, etc.)."""
    
    data_category = PolicyVariable("data_category", "string", "Category of data being processed")
    processing_purpose = PolicyVariable("processing_purpose", "string", "Purpose of processing")
    has_dpia = PolicyVariable("has_dpia", "bool", "Whether DPIA completed")
    is_high_risk_ai = PolicyVariable("is_high_risk_ai", "bool", "Whether system is high-risk AI")
    human_oversight = PolicyVariable("human_oversight", "bool", "Whether human oversight enabled")
    
    rules = [
        PolicyRule(
            id="compliance_001",
            name="AI Act - High Risk AI",
            policy_type=PolicyType.COMPLIANCE,
            description="High risk AI requires human oversight",
            variables=[is_high_risk_ai, human_oversight],
            precondition=None,
            condition=PolicyExpression(
                LogicalOperator.IMPLIES,
                [
                    PolicyCondition("is_high_risk_ai", ComparisonOperator.EQ, True),
                    PolicyCondition("human_oversight", ComparisonOperator.EQ, True),
                ]
            ),
            action="deny",
            priority=100,
        ),
        PolicyRule(
            id="compliance_002",
            name="GDPR - Special Category Data",
            policy_type=PolicyType.COMPLIANCE,
            description="Special category data requires DPIA",
            variables=[data_category, has_dpia],
            precondition=None,
            condition=PolicyExpression(
                LogicalOperator.IMPLIES,
                [
                    PolicyCondition("data_category", ComparisonOperator.IN, ["health", "biometric", "genetic"]),
                    PolicyCondition("has_dpia", ComparisonOperator.EQ, True),
                ]
            ),
            action="deny",
            priority=100,
        ),
    ]
    
    return PolicySet(
        id="guardrail_compliance_v1",
        name="Guardrail Compliance Policy Set v1",
        version="1.0.0",
        rules=rules,
    )


class PolicyParseError(Exception):
    """Error parsing policy DSL."""
    pass


def parse_policy_dsl(dsl: str) -> PolicySet:
    """Parse a policy DSL string into a PolicySet."""
    raise NotImplementedError("DSL parser not yet implemented. Use Python API directly.")


def condition(var: str, op: ComparisonOperator, value: Any, desc: str = "") -> PolicyCondition:
    """Helper to create a condition."""
    return PolicyCondition(var, op, value, desc)


def and_expr(*operands: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]) -> PolicyExpression:
    """Helper to create AND expression."""
    return PolicyExpression(LogicalOperator.AND, list(operands))


def or_expr(*operands: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]) -> PolicyExpression:
    """Helper to create OR expression."""
    return PolicyExpression(LogicalOperator.OR, list(operands))


def not_expr(operand: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]) -> PolicyExpression:
    """Helper to create NOT expression."""
    return PolicyExpression(LogicalOperator.NOT, [operand])


def implies(premise: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition], 
            conclusion: Union[PolicyExpression, PolicyCondition, TemporalPolicyCondition]) -> PolicyExpression:
    """Helper to create IMPLIES expression."""
    return PolicyExpression(LogicalOperator.IMPLIES, [premise, conclusion])


def variable(name: str, type: str, desc: str = "") -> PolicyVariable:
    """Helper to create a variable."""
    return PolicyVariable(name, type, desc)


def temporal_always(operand: Union[PolicyExpression, PolicyCondition], duration: Optional[int] = None) -> TemporalPolicyCondition:
    """Helper to create ALWAYS temporal condition."""
    return TemporalPolicyCondition(TemporalOperator.ALWAYS, operand, duration)


def temporal_eventually(operand: Union[PolicyExpression, PolicyCondition], duration: Optional[int] = None) -> TemporalPolicyCondition:
    """Helper to create EVENTUALLY temporal condition."""
    return TemporalPolicyCondition(TemporalOperator.EVENTUALLY, operand, duration)


def temporal_next(operand: Union[PolicyExpression, PolicyCondition], duration: Optional[int] = None) -> TemporalPolicyCondition:
    """Helper to create NEXT temporal condition."""
    return TemporalPolicyCondition(TemporalOperator.NEXT, operand, duration)


if __name__ == "__main__":
    safety = create_safety_policy_set()
    print(safety.to_smt_lib()[:2000])
