"""
Guardrail OS - Enterprise Human Consent & Authorization Engine
Enforces cryptographic plan integrity, role-based approval authorization, and time-bound consent boundaries.
"""

import time
import hashlib
import json
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

class ConsentStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class ConsentRequest:
    def __init__(
        self,
        plan_id: str,
        plan_description: str,
        steps: List[Any],
        risk_level: str = "low",
        user_id: str = "web_user",
        tenant_id: str = "default_tenant",
        ttl_seconds: int = 3600,
        plan_hash: Optional[str] = None
    ):
        self.plan_id = plan_id
        self.plan_description = plan_description
        self.steps_summary = steps
        self.risk_level = risk_level
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.requested_at = time.time()
        self.expires_at = self.requested_at + ttl_seconds
        self.status = ConsentStatus.PENDING
        self.plan_hash = plan_hash or self._compute_plan_hash()

    def _compute_plan_hash(self) -> str:
        canonical_str = f"{self.plan_id}:{self.plan_description}:{self.tenant_id}:{json.dumps(self.steps_summary, sort_keys=True)}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

class ConsentDecision:
    def __init__(
        self,
        plan_id: str,
        approved: bool,
        step_approvals: Optional[Dict[str, bool]] = None,
        decided_by: str = "authorized_approver",
        decider_role: str = "approver",
        decider_tenant: str = "default_tenant",
        plan_hash: Optional[str] = None
    ):
        self.plan_id = plan_id
        self.approved = approved
        self.step_approvals = step_approvals or {}
        self.decided_by = decided_by
        self.decider_role = decider_role
        self.decider_tenant = decider_tenant
        self.plan_hash = plan_hash
        self.decided_at = time.time()

class ConsentManager:
    def __init__(self):
        self.requests: Dict[str, ConsentRequest] = {}
        self.decisions: Dict[str, ConsentDecision] = {}

    def request_consent(
        self,
        plan: Any,
        user_id: str = "web_user",
        tenant_id: str = "default_tenant"
    ) -> ConsentRequest:
        steps = []
        for s in plan.steps:
            steps.append({
                "step_id": s.id,
                "description": s.description,
                "action_type": s.action_type,
                "resource": s.resource,
                "risk_level": self._assess_step_risk(s)
            })

        request = ConsentRequest(
            plan_id=plan.id,
            plan_description=plan.description,
            steps=steps,
            risk_level=self._aggregate_risk(steps),
            user_id=user_id,
            tenant_id=tenant_id
        )
        self.requests[plan.id] = request
        return request

    def process_consent(self, plan_id: str, decision: ConsentDecision) -> Tuple[bool, str]:
        if plan_id not in self.requests:
            return False, "Plan ID not found in active consent requests"

        request = self.requests[plan_id]

        # 1. Temporal integrity check
        if request.is_expired():
            request.status = ConsentStatus.EXPIRED
            return False, "Consent request has expired (TTL exceeded)"

        # 2. Terminal state lock
        if request.status in [ConsentStatus.APPROVED, ConsentStatus.DENIED]:
            return False, f"Consent already finalized with status: {request.status.value}"

        # 3. Plan version / hash binding check (Anti-Tampering)
        if decision.plan_hash and decision.plan_hash != request.plan_hash:
            return False, "Plan hash mismatch: Attempted to approve a modified or superseded plan"

        # 4. Approver tenant authorization check
        if request.tenant_id != "default_tenant" and decision.decider_tenant != request.tenant_id and decision.decider_role != "super_admin":
            return False, f"Cross-tenant authorization denied: decider belongs to {decision.decider_tenant}, plan belongs to {request.tenant_id}"

        # 5. Role authorization check
        allowed_roles = ["admin", "security_officer", "approver", "tenant_owner", "operator"]
        if decision.decider_role not in allowed_roles:
            return False, f"Insufficient role: {decision.decider_role} cannot grant execution consent"

        # Record finalized decision
        request.status = ConsentStatus.APPROVED if decision.approved else ConsentStatus.DENIED
        self.decisions[plan_id] = decision
        return True, "Consent successfully recorded"

    def _assess_step_risk(self, step: Any) -> str:
        action = getattr(step, "action_type", "")
        resource = getattr(step, "resource", "")
        if action in ["shell_command", "container_spawn", "system_reboot", "credential_rotate"]:
            return "high"
        if action in ["file_write", "file_delete", "http_post", "http_put", "http_delete"]:
            return "medium"
        if "/etc/" in resource or "/sys/" in resource or "/root" in resource:
            return "high"
        return "low"

    def _aggregate_risk(self, steps: List[Dict[str, Any]]) -> str:
        if any(s.get("risk_level") == "high" for s in steps):
            return "high"
        if any(s.get("risk_level") == "medium" for s in steps):
            return "medium"
        return "low"

_consent_manager = None

def get_consent_manager() -> ConsentManager:
    global _consent_manager
    if _consent_manager is None:
        _consent_manager = ConsentManager()
    return _consent_manager
