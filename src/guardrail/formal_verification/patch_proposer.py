"""LLM-guided Patch Proposer for Guardrail (VEPA-style).

Generates policy patches when verification fails, using an LLM to propose
fixes that maintain formal correctness.
"""
import logging
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from enum import Enum
from abc import ABC, abstractmethod

from guardrail.formal_verification.policy_language import (
    PolicySet, PolicyRule, PolicyCondition, PolicyExpression,
    PolicyVariable, PolicyType, LogicalOperator, ComparisonOperator,
    condition, and_expr, or_expr, not_expr, implies, variable,
)
from guardrail.formal_verification.verifier import (
    VerificationResult, VerificationReport, PolicyConflict,
    create_verifier, Z3Verifier, MockVerifier,
)

logger = logging.getLogger(__name__)


class PatchType(Enum):
    """Type of policy patch."""
    ADD_RULE = "add_rule"
    REMOVE_RULE = "remove_rule"
    MODIFY_RULE = "modify_rule"
    ADJUST_PRIORITY = "adjust_priority"
    ADD_VARIABLE = "add_variable"
    MODIFY_CONDITION = "modify_condition"


@dataclass
class PolicyPatch:
    """A proposed patch to a policy set."""
    id: str
    patch_type: PatchType
    target_rule_id: Optional[str]  # Rule to modify/remove, or None for add
    description: str
    changes: Dict[str, Any]  # Specific changes
    justification: str
    confidence: float  # 0.0 - 1.0
    estimated_impact: str  # "low", "medium", "high"
    
    def __post_init__(self):
        if not self.id:
            content = f"{self.patch_type.value}:{self.target_rule_id}:{self.description}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:12]


@dataclass
class PatchProposal:
    """A complete patch proposal with multiple patches."""
    id: str
    trigger_report: VerificationReport  # The verification failure that triggered this
    patches: List[PolicyPatch]
    overall_confidence: float
    rationale: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class LLMReasoner(ABC):
    """Abstract base for LLM-based reasoning."""
    
    @abstractmethod
    def propose_patches(
        self,
        policy_set: PolicySet,
        report: VerificationReport,
        conflicts: List[PolicyConflict],
    ) -> List[PolicyPatch]:
        """Generate policy patches to fix verification issues."""
        pass
    
    @abstractmethod
    def explain_conflict(
        self,
        conflict: PolicyConflict,
        rule1: PolicyRule,
        rule2: PolicyRule,
    ) -> str:
        """Explain a policy conflict in natural language."""
        pass


class MockLLMReasoner(LLMReasoner):
    """Mock LLM reasoner for testing without API calls."""
    
    def propose_patches(
        self,
        policy_set: PolicySet,
        report: VerificationReport,
        conflicts: List[PolicyConflict],
    ) -> List[PolicyPatch]:
        patches = []
        
        if report.result == VerificationResult.UNSAT:
            # Policy is unsatisfiable - suggest relaxing constraints
            patches.append(PolicyPatch(
                id="patch_relax_001",
                patch_type=PatchType.MODIFY_CONDITION,
                target_rule_id=None,
                description="Relax conflicting constraints to restore satisfiability",
                changes={"strategy": "relax_lowest_priority"},
                justification="Policy set is unsatisfiable; need to relax at least one rule",
                confidence=0.7,
                estimated_impact="medium",
            ))
        
        for conflict in conflicts:
            if conflict.conflict_type == "direct":
                # Direct conflict - suggest priority adjustment
                patches.append(PolicyPatch(
                    id=f"patch_priority_{conflict.rule1_id}_{conflict.rule2_id}",
                    patch_type=PatchType.ADJUST_PRIORITY,
                    target_rule_id=conflict.rule2_id,
                    description=f"Adjust priority to resolve conflict between {conflict.rule1_id} and {conflict.rule2_id}",
                    changes={"new_priority": "auto"},
                    justification="Direct conflict detected; priority adjustment can resolve",
                    confidence=0.8,
                    estimated_impact="low",
                ))
            elif conflict.conflict_type == "priority":
                # Priority conflict - suggest explicit ordering
                patches.append(PolicyPatch(
                    id=f"patch_explicit_{conflict.rule1_id}_{conflict.rule2_id}",
                    patch_type=PatchType.MODIFY_RULE,
                    target_rule_id=conflict.rule2_id,
                    description=f"Add explicit condition to prevent overlap",
                    changes={"add_exclusion": conflict.rule1_id},
                    justification="Rules have overlapping conditions with opposite actions",
                    confidence=0.75,
                    estimated_impact="medium",
                ))
        
        return patches
    
    def explain_conflict(
        self,
        conflict: PolicyConflict,
        rule1: PolicyRule,
        rule2: PolicyRule,
    ) -> str:
        return (
            f"Conflict between '{rule1.name}' ({rule1.id}) and '{rule2.name}' ({rule2.id}): "
            f"{conflict.description}. Type: {conflict.conflict_type}."
        )


class PatchProposer:
    """Generates policy patches using LLM guidance."""
    
    def __init__(
        self,
        llm_reasoner: Optional[LLMReasoner] = None,
        verifier: Optional[Any] = None,
        max_patches: int = 5,
    ):
        self.llm_reasoner = llm_reasoner or MockLLMReasoner()
        self.verifier = verifier or create_verifier()
        self.max_patches = max_patches
        self.patch_history: List[PatchProposal] = []
    
    def propose(
        self,
        policy_set: PolicySet,
        report: VerificationReport,
    ) -> PatchProposal:
        """Generate patch proposal for a verification failure."""
        conflicts = self.verifier.check_rule_conflicts(policy_set)
        
        # Get LLM-proposed patches
        llm_patches = self.llm_reasoner.propose_patches(policy_set, report, conflicts)
        
        # Filter and rank patches
        ranked_patches = self._rank_patches(llm_patches, policy_set, report)
        
        # Limit to max_patches
        final_patches = ranked_patches[:self.max_patches]
        
        # Calculate overall confidence
        overall_confidence = sum(p.confidence for p in final_patches) / len(final_patches) if final_patches else 0.0
        
        proposal = PatchProposal(
            id=hashlib.sha256(f"{policy_set.id}:{report.policy_id}".encode()).hexdigest()[:12],
            trigger_report=report,
            patches=final_patches,
            overall_confidence=overall_confidence,
            rationale=self._generate_rationale(final_patches, report, conflicts),
            metadata={
                "policy_id": policy_set.id,
                "report_id": report.policy_id,
                "conflicts_count": len(conflicts),
            },
        )
        
        self.patch_history.append(proposal)
        return proposal
    
    def _rank_patches(
        self,
        patches: List[PolicyPatch],
        policy_set: PolicySet,
        report: VerificationReport,
    ) -> List[PolicyPatch]:
        """Rank patches by confidence and estimated impact."""
        def score(patch: PolicyPatch) -> float:
            impact_score = {"low": 1.0, "medium": 0.7, "high": 0.4}.get(patch.estimated_impact, 0.5)
            return patch.confidence * impact_score
        
        return sorted(patches, key=score, reverse=True)
    
    def _generate_rationale(
        self,
        patches: List[PolicyPatch],
        report: VerificationReport,
        conflicts: List[PolicyConflict],
    ) -> str:
        """Generate human-readable rationale for the proposal."""
        lines = [
            f"Patch proposal for {report.policy_id} (result: {report.result.value})",
            f"Triggered by: {report.message}",
            f"Conflicts found: {len(conflicts)}",
            "",
            "Proposed patches:",
        ]
        
        for i, patch in enumerate(patches, 1):
            lines.append(f"  {i}. [{patch.patch_type.value}] {patch.description}")
            lines.append(f"     Confidence: {patch.confidence:.0%}, Impact: {patch.estimated_impact}")
            lines.append(f"     Justification: {patch.justification}")
        
        return "\n".join(lines)
    
    def apply_patch(
        self,
        policy_set: PolicySet,
        patch: PolicyPatch,
    ) -> PolicySet:
        """Apply a patch to create a new policy set (immutable)."""
        new_rules = list(policy_set.rules)
        
        if patch.patch_type == PatchType.ADD_RULE:
            new_rule = patch.changes.get("rule")
            if new_rule and isinstance(new_rule, PolicyRule):
                new_rules.append(new_rule)
        
        elif patch.patch_type == PatchType.REMOVE_RULE:
            target_id = patch.target_rule_id
            new_rules = [r for r in new_rules if r.id != target_id]
        
        elif patch.patch_type == PatchType.MODIFY_RULE:
            target_id = patch.target_rule_id
            for i, rule in enumerate(new_rules):
                if rule.id == target_id:
                    # Create modified rule
                    changes = patch.changes
                    new_rule = PolicyRule(
                        id=rule.id,
                        name=changes.get("name", rule.name),
                        policy_type=changes.get("policy_type", rule.policy_type),
                        description=changes.get("description", rule.description),
                        variables=changes.get("variables", rule.variables),
                        precondition=changes.get("precondition", rule.precondition),
                        condition=changes.get("condition", rule.condition),
                        action=changes.get("action", rule.action),
                        priority=changes.get("priority", rule.priority),
                        evidence_required=changes.get("evidence_required", rule.evidence_required),
                        metadata=changes.get("metadata", rule.metadata),
                    )
                    new_rules[i] = new_rule
                    break
        
        elif patch.patch_type == PatchType.ADJUST_PRIORITY:
            target_id = patch.target_rule_id
            for i, rule in enumerate(new_rules):
                if rule.id == target_id:
                    new_priority = patch.changes.get("new_priority")
                    if new_priority == "auto":
                        # Set priority just above conflicting rule
                        new_priority = rule.priority + 1
                    elif new_priority is None:
                        new_priority = rule.priority + 1
                    new_rules[i] = PolicyRule(
                        id=rule.id,
                        name=rule.name,
                        policy_type=rule.policy_type,
                        description=rule.description,
                        variables=rule.variables,
                        precondition=rule.precondition,
                        condition=rule.condition,
                        action=rule.action,
                        priority=new_priority,
                        evidence_required=rule.evidence_required,
                        metadata=rule.metadata,
                    )
                    break
        
        elif patch.patch_type == PatchType.MODIFY_CONDITION:
            target_id = patch.target_rule_id
            if target_id:
                for i, rule in enumerate(new_rules):
                    if rule.id == target_id:
                        new_condition = patch.changes.get("condition")
                        if new_condition:
                            new_rules[i] = PolicyRule(
                                id=rule.id,
                                name=rule.name,
                                policy_type=rule.policy_type,
                                description=rule.description,
                                variables=rule.variables,
                                precondition=rule.precondition,
                                condition=new_condition,
                                action=rule.action,
                                priority=rule.priority,
                                evidence_required=rule.evidence_required,
                                metadata=rule.metadata,
                            )
                            break
            else:
                # Global relaxation - lower priority of all deny rules slightly
                for i, rule in enumerate(new_rules):
                    if rule.action == "deny" and rule.priority > 10:
                        new_rules[i] = PolicyRule(
                            id=rule.id,
                            name=rule.name,
                            policy_type=rule.policy_type,
                            description=rule.description,
                            variables=rule.variables,
                            precondition=rule.precondition,
                            condition=rule.condition,
                            action=rule.action,
                            priority=rule.priority - 5,
                            evidence_required=rule.evidence_required,
                            metadata=rule.metadata,
                        )
        
        return PolicySet(
            id=policy_set.id,
            name=policy_set.name + " (patched)",
            version=self._increment_version(policy_set.version),
            rules=new_rules,
            metadata={**policy_set.metadata, "patched_from": policy_set.id},
        )
    
    def _increment_version(self, version: str) -> str:
        """Increment patch version."""
        try:
            parts = version.split(".")
            parts[-1] = str(int(parts[-1]) + 1)
            return ".".join(parts)
        except:
            return version + ".1"
    
    def validate_patch(
        self,
        policy_set: PolicySet,
        patch: PolicyPatch,
    ) -> VerificationReport:
        """Validate that a patch fixes the issue."""
        new_policy = self.apply_patch(policy_set, patch)
        return self.verifier.verify_policy_set(new_policy)
    
    def auto_fix(
        self,
        policy_set: PolicySet,
        report: VerificationReport,
    ) -> Tuple[Optional[PolicySet], PatchProposal]:
        """Attempt to automatically fix a policy set."""
        proposal = self.propose(policy_set, report)
        
        for patch in proposal.patches:
            new_policy = self.apply_patch(policy_set, patch)
            validation = self.verifier.verify_policy_set(new_policy)
            
            if validation.result == VerificationResult.SAT:
                logger.info(f"Patch {patch.id} successfully fixed policy")
                return new_policy, proposal
            else:
                logger.warning(f"Patch {patch.id} did not fix: {validation.message}")
        
        logger.warning("No patches successfully fixed the policy")
        return None, proposal


# Type alias for cleaner imports
from typing import Tuple

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create policy and verifier
    from guardrail.formal_verification.policy_language import create_safety_policy_set
    from guardrail.formal_verification.verifier import create_verifier
    
    safety = create_safety_policy_set()
    verifier = create_verifier()
    
    # Verify
    report = verifier.verify_policy_set(safety)
    print(f"Initial verification: {report.result.value}")
    
    # Create proposer
    proposer = PatchProposer(verifier=verifier)
    
    # Generate patches (even though policy is SAT, for demo)
    proposal = proposer.propose(safety, report)
    print(f"\nProposal: {proposal.id}")
    print(f"Rationale:\n{proposal.rationale}")
    
    # Test with a deliberately conflicting policy
    print("\n=== Testing with conflicting rules ===")
    from guardrail.formal_verification.policy_language import PolicyRule, PolicyCondition, PolicyExpression, LogicalOperator, ComparisonOperator
    
    # Add a conflicting rule
    conflict_rule = PolicyRule(
        id="conflict_001",
        name="Allow All Admin",
        policy_type=PolicyType.SAFETY,
        description="Allow all admin actions",
        variables=[
            variable("requires_admin", "bool"),
            variable("user_consent", "bool"),
        ],
        precondition=PolicyCondition("requires_admin", ComparisonOperator.EQ, True),
        condition=PolicyCondition("user_consent", ComparisonOperator.EQ, False),  # Allows without consent!
        action="allow",
        priority=200,  # Higher than safety_001 (100)
    )
    
    conflicted_policy = PolicySet(
        id="conflicted_test",
        name="Conflicted Policy",
        version="1.0.0",
        rules=safety.rules + [conflict_rule],
    )
    
    report2 = verifier.verify_policy_set(conflicted_policy)
    print(f"Conflicted verification: {report2.result.value}")
    
    if report2.result == VerificationResult.UNSAT:
        conflicts = verifier.check_rule_conflicts(conflicted_policy)
        print(f"Conflicts: {len(conflicts)}")
        for c in conflicts:
            print(f"  {c.rule1_id} vs {c.rule2_id}: {c.conflict_type}")
        
        proposal2 = proposer.propose(conflicted_policy, report2)
        print(f"\nProposal: {proposal2.id}")
        print(f"Patches: {len(proposal2.patches)}")
        print(f"Rationale:\n{proposal2.rationale}")
        
        # Try auto-fix
        fixed_policy, _ = proposer.auto_fix(conflicted_policy, report2)
        if fixed_policy:
            report3 = verifier.verify_policy_set(fixed_policy)
            print(f"Fixed verification: {report3.result.value}")