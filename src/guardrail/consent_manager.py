import time
from enum import Enum
from typing import List, Dict, Any, Optional

class ConsentStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class ConsentRequest:
    def __init__(self, plan_id: str, plan_description: str, steps: List[Any], risk_level: str = "low"):
        self.plan_id = plan_id
        self.plan_description = plan_description
        self.steps_summary = steps
        self.risk_level = risk_level
        self.requested_at = time.time()
        self.status = ConsentStatus.PENDING

class ConsentDecision:
    def __init__(self, plan_id: str, approved: bool, step_approvals: Dict[str, bool] = None, decided_by: str = "user"):
        self.plan_id = plan_id
        self.approved = approved
        self.step_approvals = step_approvals or {}
        self.decided_by = decided_by

class ConsentManager:
    def __init__(self):
        self.requests: Dict[str, ConsentRequest] = {}

    def request_consent(self, plan: Any) -> ConsentRequest:
        steps = []
        for s in plan.steps:
            steps.append({
                "step_id": s.id,
                "description": s.description,
                "action_type": s.action_type,
                "resource": s.resource,
                "risk_level": self._assess_step_risk(s)
            })
        
        request = ConsentRequest(plan.id, plan.description, steps)
        self.requests[plan.id] = request
        return request

    def process_consent(self, plan_id: str, decision: ConsentDecision) -> bool:
        if plan_id not in self.requests:
            return False
        
        request = self.requests[plan_id]
        request.status = ConsentStatus.APPROVED if decision.approved else ConsentStatus.DENIED
        return True

    def _assess_step_risk(self, step: Any) -> str:
        if step.action_type == "shell_command":
            return "high"
        if step.action_type == "file_write":
            return "medium"
        return "low"

_consent_manager = None

def get_consent_manager() -> ConsentManager:
    global _consent_manager
    if _consent_manager is None:
        _consent_manager = ConsentManager()
    return _consent_manager
