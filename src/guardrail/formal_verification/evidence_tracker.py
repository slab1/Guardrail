"""Evidence-Aware Activation Layer for Guardrail (VEPA-style).

Tracks evidence for policy rule activation to prevent uncertain rules
from firing. Based on VEPA's evidence-aware activation mechanism.
"""
import logging
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Callable, Tuple
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

from guardrail.formal_verification.policy_language import (
    PolicySet, PolicyRule, PolicyCondition, PolicyExpression,
    PolicyVariable, PolicyType, LogicalOperator, ComparisonOperator,
    variable, condition, and_expr, or_expr, not_expr, implies,
)
from guardrail.formal_verification.verifier import (
    VerificationResult, VerificationReport, create_verifier,
)

logger = logging.getLogger(__name__)


class EvidenceType(Enum):
    """Types of evidence for rule activation."""
    DIRECT_OBSERVATION = "direct_observation"    # Directly observed fact
    LOGGED_EVENT = "logged_event"                # Event from audit log
    USER_CONSENT = "user_consent"                # Explicit user consent
    CRYPTOGRAPHIC_PROOF = "cryptographic_proof"  # Signed attestation
    EXTERNAL_VERIFICATION = "external_verification"  # Third-party verification
    INFERRED = "inferred"                        # Inferred from other evidence
    TEMPORAL = "temporal"                        # Time-based evidence


class EvidenceStrength(Enum):
    """Strength of evidence."""
    WEAK = 0.3
    MODERATE = 0.6
    STRONG = 0.9
    DEFINITIVE = 1.0


@dataclass
class Evidence:
    """A piece of evidence supporting a fact."""
    id: str
    fact: str                          # The fact this evidence supports
    evidence_type: EvidenceType
    strength: EvidenceStrength
    source: str                        # Source of evidence (e.g., "audit_log", "user_input")
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[float] = None  # Expiration timestamp
    
    def __post_init__(self):
        if not self.id:
            content = f"{self.fact}:{self.source}:{self.timestamp}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def is_valid(self, current_time: Optional[float] = None) -> bool:
        """Check if evidence is still valid."""
        if self.expires_at is None:
            return True
        now = current_time or time.time()
        return now < self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "fact": self.fact,
            "type": self.evidence_type.value,
            "strength": self.strength.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "expires_at": self.expires_at,
        }


@dataclass
class EvidenceChain:
    """A chain of evidence supporting a conclusion."""
    conclusion: str
    evidence_ids: List[str]
    combined_strength: float
    reasoning: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "conclusion": self.conclusion,
            "evidence_ids": self.evidence_ids,
            "combined_strength": self.combined_strength,
            "reasoning": self.reasoning,
        }


class EvidenceStore:
    """Stores and manages evidence."""
    
    def __init__(self):
        self._evidence: Dict[str, Evidence] = {}
        self._fact_to_evidence: Dict[str, Set[str]] = defaultdict(set)
        self._chains: List[EvidenceChain] = []
    
    def add(self, evidence: Evidence) -> str:
        """Add evidence to the store."""
        self._evidence[evidence.id] = evidence
        self._fact_to_evidence[evidence.fact].add(evidence.id)
        return evidence.id
    
    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)
    
    def get_for_fact(self, fact: str) -> List[Evidence]:
        """Get all evidence for a fact."""
        ids = self._fact_to_evidence.get(fact, set())
        return [self._evidence[eid] for eid in ids if eid in self._evidence]
    
    def get_valid_for_fact(self, fact: str, current_time: Optional[float] = None) -> List[Evidence]:
        """Get valid evidence for a fact."""
        return [e for e in self.get_for_fact(fact) if e.is_valid(current_time)]
    
    def get_strongest_for_fact(self, fact: str, current_time: Optional[float] = None) -> Optional[Evidence]:
        """Get the strongest valid evidence for a fact."""
        valid = self.get_valid_for_fact(fact, current_time)
        if not valid:
            return None
        return max(valid, key=lambda e: e.strength.value)
    
    def add_chain(self, chain: EvidenceChain):
        """Add an evidence chain."""
        self._chains.append(chain)
    
    def get_chains_for_conclusion(self, conclusion: str) -> List[EvidenceChain]:
        """Get all chains for a conclusion."""
        return [c for c in self._chains if c.conclusion == conclusion]
    
    def cleanup_expired(self, current_time: Optional[float] = None) -> int:
        """Remove expired evidence."""
        now = current_time or time.time()
        expired_ids = [
            eid for eid, e in self._evidence.items()
            if not e.is_valid(now)
        ]
        for eid in expired_ids:
            e = self._evidence.pop(eid)
            self._fact_to_evidence[e.fact].discard(eid)
        return len(expired_ids)


@dataclass
class ActivationContext:
    """Context for rule activation decisions."""
    action_vars: Dict[str, Any]           # Variables for the action being checked
    evidence_store: EvidenceStore         # Available evidence
    policy_set: PolicySet                 # Policy set being evaluated
    rule: PolicyRule                      # Rule being evaluated
    required_evidence: List[str]          # Required evidence types for this rule
    min_strength: float = 0.6             # Minimum evidence strength
    metadata: Dict[str, Any] = field(default_factory=dict)


class ActivationStrategy(ABC):
    """Strategy for determining if a rule should activate based on evidence."""
    
    @abstractmethod
    def should_activate(self, context: ActivationContext) -> Tuple[bool, str, List[str]]:
        """
        Determine if rule should activate.
        
        Returns: (should_activate, reason, evidence_ids_used)
        """
        pass


class RequireAllEvidenceStrategy(ActivationStrategy):
    """All required evidence must be present with sufficient strength."""
    
    def should_activate(self, context: ActivationContext) -> Tuple[bool, str, List[str]]:
        used_ids = []
        
        for req in context.required_evidence:
            evidence = context.evidence_store.get_strongest_for_fact(req)
            if evidence is None:
                return False, f"Missing required evidence: {req}", []
            if evidence.strength.value < context.min_strength:
                return False, f"Evidence too weak for {req}: {evidence.strength.value}", []
            used_ids.append(evidence.id)
        
        return True, "All required evidence present with sufficient strength", used_ids


class RequireAnyEvidenceStrategy(ActivationStrategy):
    """At least one piece of required evidence must be present."""
    
    def should_activate(self, context: ActivationContext) -> Tuple[bool, str, List[str]]:
        used_ids = []
        
        for req in context.required_evidence:
            evidence = context.evidence_store.get_strongest_for_fact(req)
            if evidence and evidence.strength.value >= context.min_strength:
                used_ids.append(evidence.id)
                return True, f"Evidence found: {req}", used_ids
        
        return False, f"No valid evidence found for any required fact: {context.required_evidence}", []


class WeightedEvidenceStrategy(ActivationStrategy):
    """Weighted combination of evidence must meet threshold."""
    
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
    
    def should_activate(self, context: ActivationContext) -> Tuple[bool, str, List[str]]:
        used_ids = []
        total_weight = 0.0
        max_possible = 0.0
        
        for req in context.required_evidence:
            evidence = context.evidence_store.get_strongest_for_fact(req)
            max_possible += 1.0  # Each evidence can contribute max 1.0
            
            if evidence and evidence.strength.value >= context.min_strength:
                total_weight += evidence.strength.value
                used_ids.append(evidence.id)
        
        if max_possible == 0:
            return False, "No evidence requirements defined", []
        
        score = total_weight / max_possible
        if score >= self.threshold:
            return True, f"Weighted evidence score: {score:.2f} >= {self.threshold}", used_ids
        
        return False, f"Weighted evidence score too low: {score:.2f} < {self.threshold}", []


class TemporalEvidenceStrategy(ActivationStrategy):
    """Evidence must be recent (within time window)."""
    
    def __init__(self, max_age_seconds: float = 3600):
        self.max_age_seconds = max_age_seconds
    
    def should_activate(self, context: ActivationContext) -> Tuple[bool, str, List[str]]:
        used_ids = []
        now = time.time()
        
        for req in context.required_evidence:
            evidence = context.evidence_store.get_strongest_for_fact(req)
            if evidence is None:
                return False, f"Missing required evidence: {req}", []
            
            age = now - evidence.timestamp
            if age > self.max_age_seconds:
                return False, f"Evidence too old: {req} (age: {age:.0f}s > {self.max_age_seconds}s)", []
            
            if evidence.strength.value < context.min_strength:
                return False, f"Evidence too weak for {req}", []
            
            used_ids.append(evidence.id)
        
        return True, "All required evidence is recent and strong enough", used_ids


class EvidenceAwareActivator:
    """Main class for evidence-aware rule activation."""
    
    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        default_strategy: Optional[ActivationStrategy] = None,
        min_strength: float = 0.6,
    ):
        self.evidence_store = evidence_store or EvidenceStore()
        self.default_strategy = default_strategy or RequireAllEvidenceStrategy()
        self.min_strength = min_strength
        self.rule_strategies: Dict[str, ActivationStrategy] = {}
        self.activation_log: List[Dict[str, Any]] = []
    
    def set_strategy_for_rule(self, rule_id: str, strategy: ActivationStrategy):
        """Set a custom activation strategy for a specific rule."""
        self.rule_strategies[rule_id] = strategy
    
    def add_evidence(self, evidence: Evidence) -> str:
        """Add evidence to the store."""
        return self.evidence_store.add(evidence)
    
    def add_evidence_simple(
        self,
        fact: str,
        evidence_type: EvidenceType,
        strength: EvidenceStrength,
        source: str,
        metadata: Optional[Dict[str, Any]] = None,
        expires_in: Optional[float] = None,
    ) -> str:
        """Add evidence with simple parameters."""
        expires_at = None
        if expires_in:
            expires_at = time.time() + expires_in
        
        evidence = Evidence(
            id="",
            fact=fact,
            evidence_type=evidence_type,
            strength=strength,
            source=source,
            metadata=metadata or {},
            expires_at=expires_at,
        )
        return self.add_evidence(evidence)
    
    def evaluate_rule(
        self,
        policy_set: PolicySet,
        rule: PolicyRule,
        action_vars: Dict[str, Any],
        required_evidence: Optional[List[str]] = None,
        strategy: Optional[ActivationStrategy] = None,
    ) -> Tuple[bool, str, List[str]]:
        """Evaluate if a rule should activate given evidence."""
        
        # Determine required evidence
        req_evidence = required_evidence or rule.evidence_required
        
        if not req_evidence:
            # No evidence required - use default strategy or allow
            if strategy is None:
                strategy = self.default_strategy
            # Create dummy context
            context = ActivationContext(
                action_vars=action_vars,
                evidence_store=self.evidence_store,
                policy_set=policy_set,
                rule=rule,
                required_evidence=[],
                min_strength=self.min_strength,
            )
            return strategy.should_activate(context)
        
        # Use rule-specific strategy or default
        if strategy is None:
            strategy = self.rule_strategies.get(rule.id, self.default_strategy)
        
        context = ActivationContext(
            action_vars=action_vars,
            evidence_store=self.evidence_store,
            policy_set=policy_set,
            rule=rule,
            required_evidence=req_evidence,
            min_strength=self.min_strength,
        )
        
        should_activate, reason, used_ids = strategy.should_activate(context)
        
        # Log activation decision
        self.activation_log.append({
            "timestamp": time.time(),
            "rule_id": rule.id,
            "rule_name": rule.name,
            "should_activate": should_activate,
            "reason": reason,
            "evidence_used": used_ids,
            "action_vars": action_vars,
        })
        
        return should_activate, reason, used_ids
    
    def evaluate_policy(
        self,
        policy_set: PolicySet,
        action_vars: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate all rules in a policy set with evidence awareness."""
        
        results = {
            "allowed": True,
            "denied_rules": [],
            "approval_required_rules": [],
            "activated_rules": [],
            "skipped_rules": [],
            "evidence_summary": {},
        }
        
        for rule in sorted(policy_set.rules, key=lambda r: -r.priority):
            req_evidence = rule.evidence_required
            strategy = self.rule_strategies.get(rule.id)
            
            should_activate, reason, used_ids = self.evaluate_rule(
                policy_set, rule, action_vars, req_evidence, strategy
            )
            
            if not should_activate:
                results["skipped_rules"].append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "action": rule.action,
                    "reason": reason,
                })
                continue
            
            results["activated_rules"].append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "action": rule.action,
                "reason": reason,
                "evidence_used": used_ids,
            })
            
            # Record evidence summary
            for eid in used_ids:
                evidence = self.evidence_store.get(eid)
                if evidence:
                    results["evidence_summary"][eid] = evidence.to_dict()
            
            # Check if this rule affects the final decision
            if rule.action == "deny":
                results["allowed"] = False
                results["denied_rules"].append(rule.id)
                # In deny-by-default, first deny stops evaluation
                break
            elif rule.action == "require_approval":
                results["approval_required_rules"].append(rule.id)
        
        return results
    
    def get_activation_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent activation log."""
        return self.activation_log[-limit:]


class EvidenceAwareVerifier:
    """Verifier that integrates with evidence-aware activation."""
    
    def __init__(
        self,
        verifier: Any = None,
        activator: Optional[EvidenceAwareActivator] = None,
    ):
        self.verifier = verifier or create_verifier()
        self.activator = activator or EvidenceAwareActivator()
    
    def verify_with_evidence(
        self,
        policy_set: PolicySet,
        action_vars: Dict[str, Any],
        evidence: Optional[List[Evidence]] = None,
    ) -> Dict[str, Any]:
        """Verify an action with evidence-aware activation."""
        
        # Add provided evidence
        if evidence:
            for e in evidence:
                self.activator.add_evidence(e)
        
        # First do formal verification
        formal_report = self.verifier.verify_policy_set(policy_set)
        
        # Then do evidence-aware evaluation
        activation_result = self.activator.evaluate_policy(policy_set, action_vars)
        
        # Combine results
        return {
            "formal_verification": {
                "result": formal_report.result.value,
                "message": formal_report.message,
                "execution_time_ms": formal_report.execution_time_ms,
            },
            "evidence_activation": activation_result,
            "final_allowed": formal_report.result == VerificationResult.SAT and activation_result["allowed"],
            "evidence_store_size": len(self.activator.evidence_store._evidence),
        }


# ----------------------------------------------------------------------
# Example Usage
# ----------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    from guardrail.formal_verification.policy_language import create_safety_policy_set
    
    # Create policy and activator
    safety = create_safety_policy_set()
    activator = EvidenceAwareActivator(min_strength=0.6)
    
    # Add some evidence
    activator.add_evidence_simple(
        fact="user_consent_given",
        evidence_type=EvidenceType.USER_CONSENT,
        strength=EvidenceStrength.STRONG,
        source="consent_ui",
        metadata={"user_id": "user123", "plan_id": "plan_001"},
        expires_in=3600,
    )
    
    activator.add_evidence_simple(
        fact="admin_action_requested",
        evidence_type=EvidenceType.DIRECT_OBSERVATION,
        strength=EvidenceStrength.DEFINITIVE,
        source="action_logger",
        metadata={"action": "file_delete", "path": "/etc/config.yaml"},
    )
    
    # Add rule-specific strategies
    activator.set_strategy_for_rule("safety_001", RequireAllEvidenceStrategy())
    activator.set_strategy_for_rule("safety_002", RequireAllEvidenceStrategy())
    
    # Test action that requires evidence
    action = {
        "action_type": "file_delete",
        "autonomy_level": 3,
        "user_consent": True,
        "requires_admin": True,
    }
    
    result = activator.evaluate_policy(safety, action)
    print(f"Action: file_delete @ L3 with consent")
    print(f"Allowed: {result['allowed']}")
    print(f"Activated rules: {len(result['activated_rules'])}")
    print(f"Skipped rules: {len(result['skipped_rules'])}")
    print(f"Denied rules: {result['denied_rules']}")
    print(f"Approval required: {result['approval_required_rules']}")
    
    # Show evidence summary
    print("\nEvidence used:")
    for eid, edict in result["evidence_summary"].items():
        print(f"  {eid}: {edict['fact']} ({edict['type']}) strength={edict['strength']}")
    
    # Test without consent
    print("\n--- Without user consent ---")
    action_no_consent = {
        "action_type": "file_delete",
        "autonomy_level": 3,
        "user_consent": False,
        "requires_admin": True,
    }
    
    # Need to clear evidence store for clean test
    activator2 = EvidenceAwareActivator(min_strength=0.6)
    activator2.set_strategy_for_rule("safety_001", RequireAllEvidenceStrategy())
    activator2.set_strategy_for_rule("safety_002", RequireAllEvidenceStrategy())
    
    # Add only admin action evidence (no consent)
    activator2.add_evidence_simple(
        fact="admin_action_requested",
        evidence_type=EvidenceType.DIRECT_OBSERVATION,
        strength=EvidenceStrength.DEFINITIVE,
        source="action_logger",
        metadata={"action": "file_delete", "path": "/etc/config.yaml"},
    )
    
    result2 = activator2.evaluate_policy(safety, action_no_consent)
    print(f"Action: file_delete @ L3 WITHOUT consent")
    print(f"Allowed: {result2['allowed']}")
    print(f"Activated rules: {len(result2['activated_rules'])}")
    print(f"Skipped rules: {len(result2['skipped_rules'])}")
    for skipped in result2["skipped_rules"]:
        print(f"  Skipped: {skipped['rule_name']} - {skipped['reason']}")
    
    # Test EvidenceAwareVerifier
    print("\n=== EvidenceAwareVerifier ===")
    from guardrail.formal_verification.verifier import create_verifier
    
    verifier = create_verifier()
    activator3 = EvidenceAwareActivator()
    activator3.add_evidence_simple(
        fact="user_consent_given",
        evidence_type=EvidenceType.USER_CONSENT,
        strength=EvidenceStrength.STRONG,
        source="consent_ui",
    )
    
    ea_verifier = EvidenceAwareVerifier(verifier, activator3)
    
    result3 = ea_verifier.verify_with_evidence(safety, action)
    print(f"Formal: {result3['formal_verification']['result']}")
    print(f"Evidence activation allowed: {result3['evidence_activation']['allowed']}")
    print(f"Final allowed: {result3['final_allowed']}")