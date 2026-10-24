"""Consent management for Guardrail - plan-level consent with UI hooks."""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from guardrail.plan_compiler.enhanced_plan_compiler import ValidatedPlan


class ConsentStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ConsentRequest:
    """Request for consent on a plan."""
    plan_id: str
    plan_description: str
    steps_summary: List[Dict[str, Any]]
    risk_level: str  # "low", "medium", "high"
    requested_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = 0
    status: ConsentStatus = ConsentStatus.PENDING
    response: Optional[Dict[str, Any]] = None


@dataclass
class ConsentDecision:
    """Result of a consent decision."""
    plan_id: str
    approved: bool
    step_approvals: Dict[str, bool] = field(default_factory=dict)  # step_id -> approved
    conditions: List[str] = field(default_factory=list)
    decided_at: int = field(default_factory=lambda: int(time.time()))
    decided_by: str = "user"


class ConsentManager:
    """Manages consent requests and decisions."""
    
    def __init__(self, default_ttl: int = 3600):  # 1 hour default
        self.default_ttl = default_ttl
        self.requests: Dict[str, ConsentRequest] = {}
        self.decisions: Dict[str, ConsentDecision] = {}
        self.ui_callback: Optional[Callable[[ConsentRequest], ConsentDecision]] = None
    
    def set_ui_callback(self, callback: Callable[[ConsentRequest], ConsentDecision]):
        """Set a UI callback for interactive consent."""
        self.ui_callback = callback
    
    def request_consent(self, vplan: ValidatedPlan, risk_level: str = "medium") -> ConsentRequest:
        """Create a consent request for a validated plan."""
        plan_id = vplan.id
        steps_summary = []
        for step in vplan.steps:
            steps_summary.append({
                "step_id": step.id,
                "description": step.description,
                "action": step.action_type,
                "resource": step.resource,
                "reversible": step.reversible,
                "risk": self._assess_step_risk(step),
            })
        
        request = ConsentRequest(
            plan_id=plan_id,
            plan_description=vplan.description,
            steps_summary=steps_summary,
            risk_level=risk_level,
            expires_at=int(time.time()) + self.default_ttl,
        )
        self.requests[plan_id] = request
        return request
    
    def _assess_step_risk(self, step) -> str:
        """Assess risk level of a single step."""
        high_risk_actions = {"file_delete", "http_delete", "shell_command", "database_update"}
        medium_risk_actions = {"file_write", "http_post", "http_put"}
        
        if step.action_type in high_risk_actions:
            return "high"
        elif step.action_type in medium_risk_actions:
            return "medium"
        return "low"
    
    def get_consent_request(self, plan_id: str) -> Optional[ConsentRequest]:
        """Get a consent request by plan ID."""
        return self.requests.get(plan_id)
    
    def process_consent(self, plan_id: str, decision: ConsentDecision) -> bool:
        """Record a consent decision."""
        if plan_id not in self.requests:
            return False
        
        request = self.requests[plan_id]
        if request.status != ConsentStatus.PENDING:
            return False
        
        if int(time.time()) > request.expires_at:
            request.status = ConsentStatus.EXPIRED
            return False
        
        request.status = ConsentStatus.APPROVED if decision.approved else ConsentStatus.DENIED
        request.response = {
            "approved": decision.approved,
            "step_approvals": decision.step_approvals,
            "conditions": decision.conditions,
            "decided_at": decision.decided_at,
            "decided_by": decision.decided_by,
        }
        self.decisions[plan_id] = decision
        return True
    
    def request_consent_interactive(self, vplan: ValidatedPlan, risk_level: str = "medium") -> ConsentDecision:
        """Request consent interactively using the UI callback."""
        request = self.request_consent(vplan, risk_level)
        
        if self.ui_callback:
            decision = self.ui_callback(request)
        else:
            # Default: auto-approve for testing
            decision = ConsentDecision(
                plan_id=vplan.id,
                approved=True,
                step_approvals={step.id: True for step in vplan.steps},
                conditions=["Auto-approved for testing"],
            )
        
        self.process_consent(vplan.id, decision)
        return decision
    
    def is_plan_approved(self, plan_id: str) -> bool:
        """Check if a plan has been approved."""
        request = self.requests.get(plan_id)
        return request is not None and request.status == ConsentStatus.APPROVED
    
    def is_step_approved(self, plan_id: str, step_id: str) -> bool:
        """Check if a specific step is approved."""
        decision = self.decisions.get(plan_id)
        if not decision:
            return False
        return decision.step_approvals.get(step_id, decision.approved)


# Default consent manager instance
_consent_manager: Optional[ConsentManager] = None


def get_consent_manager() -> ConsentManager:
    """Get the global consent manager instance."""
    global _consent_manager
    if _consent_manager is None:
        _consent_manager = ConsentManager()
    return _consent_manager


def request_plan_consent(vplan: ValidatedPlan, risk_level: str = "medium") -> ConsentRequest:
    """Convenience function to request consent for a plan."""
    return get_consent_manager().request_consent(vplan, risk_level)


def process_plan_consent(plan_id: str, decision: ConsentDecision) -> bool:
    """Convenience function to process a consent decision."""
    return get_consent_manager().process_consent(plan_id, decision)


def is_plan_approved(plan_id: str) -> bool:
    """Convenience function to check if a plan is approved."""
    return get_consent_manager().is_plan_approved(plan_id)


def is_step_approved(plan_id: str, step_id: str) -> bool:
    """Convenience function to check if a step is approved."""
    return get_consent_manager().is_step_approved(plan_id, step_id)


def request_consent_interactive(vplan: ValidatedPlan, risk_level: str = "medium") -> ConsentDecision:
    """Convenience function for interactive consent."""
    return get_consent_manager().request_consent_interactive(vplan, risk_level)


# ----------------------------------------------------------------------
# Example UI callback for testing
# ----------------------------------------------------------------------
def simple_cli_consent_callback(request: ConsentRequest) -> ConsentDecision:
    """Simple CLI-based consent callback for testing."""
    print(f"\n=== Consent Request for Plan {request.plan_id} ===")
    print(f"Description: {request.plan_description}")
    print(f"Risk Level: {request.risk_level}")
    print("\nSteps:")
    for step in request.steps_summary:
        print(f"  [{step['step_id']}] {step['description']} ({step['action']}) - Risk: {step['risk']}")
    
    # In real implementation, this would prompt the user
    # For testing, we'll auto-approve with conditions
    return ConsentDecision(
        plan_id=request.plan_id,
        approved=True,
        step_approvals={step['step_id']: True for step in request.steps_summary},
        conditions=["Approved for testing purposes"],
        decided_by="test_user",
    )


if __name__ == "__main__":
    # Test the consent system
    from guardrail.plan_compiler.enhanced_plan_compiler import compile_and_validate_plan
    
    intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    vplan = compile_and_validate_plan(intent, agent_class="coding", user_id="user123", autonomy_level=2)
    
    manager = ConsentManager()
    manager.set_ui_callback(simple_cli_consent_callback)
    
    decision = manager.request_consent_interactive(vplan, risk_level="medium")
    print(f"\nDecision: {'Approved' if decision.approved else 'Denied'}")
    print(f"Conditions: {decision.conditions}")
    print(f"Plan approved: {manager.is_plan_approved(vplan.id)}")