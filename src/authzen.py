"""AuthZEN-compatible Decision API and SPIFFE/ID-JAG Integration."""
import time
import json
import uuid
import hashlib
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from causal_audit import get_audit_logger, AuditEventType, CausalLabel
from autopilot import get_autopilot, TrustLevel
from pep_framework import PEPType


class DecisionType(Enum):
    """Types of authorization decisions."""
    PERMIT = "permit"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class SubjectType(Enum):
    """Subject types for AuthZEN."""
    USER = "user"
    AGENT = "agent"
    WORKLOAD = "workload"
    SERVICE = "service"


@dataclass
class AuthZENSubject:
    """AuthZEN subject representation."""
    subject_id: str
    subject_type: SubjectType
    spiffe_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthZENResource:
    """AuthZEN resource representation."""
    resource_id: str
    resource_type: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthZENAction:
    """AuthZEN action representation."""
    action_id: str
    action_type: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthZENContext:
    """AuthZEN request context."""
    request_id: str
    timestamp: int
    environment: Dict[str, Any] = field(default_factory=dict)
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AuthZENDecisionRequest:
    """AuthZEN decision request."""
    subject: AuthZENSubject
    resource: AuthZENResource
    action: AuthZENAction
    context: AuthZENContext


@dataclass
class AuthZENDecisionResponse:
    """AuthZEN decision response."""
    decision: DecisionType
    request_id: str
    timestamp: int
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    advice: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuthZENDecisionEngine:
    """AuthZEN-compatible decision engine integrating Guardrail policies."""
    
    def __init__(self):
        self.policies: Dict[str, Dict] = {}
        self.lock = Lock()
        self.audit_logger = get_audit_logger()
        self.autopilot = get_autopilot()
        
        # Register default policies
        self._register_default_policies()
    
    def _register_default_policies(self):
        """Register default Guardrail policies."""
        # These map to our existing policy enforcement
        pass
    
    def evaluate(self, request: AuthZENDecisionRequest) -> AuthZENDecisionResponse:
        """Evaluate an AuthZEN decision request."""
        start_time = time.time_ns()
        
        # Extract Guardrail-specific info from subject
        agent_id = request.subject.subject_id
        user_id = request.subject.attributes.get("user_id", "unknown")
        agent_class = request.subject.attributes.get("agent_class", "coding")
        autonomy_level = request.subject.attributes.get("autonomy_level", 0)
        plan_id = request.context.environment.get("plan_id")
        step_id = request.context.environment.get("step_id")
        token = request.context.environment.get("token")
        intent = request.context.environment.get("intent", "")
        
        # Log the decision request
        causal_label = None
        if plan_id and step_id:
            causal_label = CausalLabel(
                label_id=request.context.request_id,
                plan_id=plan_id,
                step_id=step_id,
                intent=intent,
                agent_class=agent_class,
                user_id=user_id,
                autonomy_level=autonomy_level,
                timestamp=int(time.time() * 1_000_000),
            )
            self.audit_logger.log_event(
                AuditEventType.CAPABILITY_CHECK,
                causal_label,
                syscall=f"authzen_decision:{request.action.action_id}",
                args={
                    "subject": request.subject.subject_id,
                    "resource": request.resource.resource_id,
                    "action": request.action.action_id,
                },
                result="pending",
            )
        
        # Evaluate using Guardrail logic
        decision = self._evaluate_guardrail(
            agent_id=agent_id,
            user_id=user_id,
            agent_class=agent_class,
            autonomy_level=autonomy_level,
            plan_id=plan_id,
            step_id=step_id,
            token=token,
            action=request.action.action_id,
            resource=request.resource.resource_id,
            intent=intent,
        )
        
        # Build AuthZEN response
        response = AuthZENDecisionResponse(
            decision=decision["decision"],
            request_id=request.context.request_id,
            timestamp=int(time.time() * 1000),
            obligations=decision.get("obligations", []),
            advice=decision.get("advice", []),
            metadata={
                "guardrail": {
                    "agent_id": agent_id,
                    "autonomy_level": autonomy_level,
                    "trust_level": decision.get("trust_level"),
                    "effective_autonomy": decision.get("effective_autonomy"),
                    "plan_id": plan_id,
                    "step_id": step_id,
                },
                "evaluation_time_ms": (time.time_ns() - start_time) / 1_000_000,
            }
        )
        
        # Log the decision result
        if causal_label:
            self.audit_logger.log_event(
                AuditEventType.CAPABILITY_CHECK,
                causal_label,
                syscall=f"authzen_decision:{request.action.action_id}",
                args={
                    "subject": request.subject.subject_id,
                    "resource": request.resource.resource_id,
                    "action": request.action.action_id,
                },
                result=decision["decision"].value,
            )
        
        return response
    
    def _evaluate_guardrail(
        self,
        agent_id: str,
        user_id: str,
        agent_class: str,
        autonomy_level: int,
        plan_id: Optional[str],
        step_id: Optional[str],
        token: Optional[str],
        action: str,
        resource: str,
        intent: str,
    ) -> Dict[str, Any]:
        """Evaluate using Guardrail policy logic."""
        
        # Check trust level / effective autonomy
        trust_status = self.autopilot.get_status(agent_id)
        effective_autonomy = trust_status.get("effective_autonomy_level", 0)
        trust_level = trust_status.get("trust_level", "LOCKED")
        
        # Check if we have plan context
        if plan_id and step_id:
            # This is a step-level decision
            if token:
                # Validate token
                from plan_compiler.enhanced_plan_compiler import validate_step_token_for_execution
                token_valid = validate_step_token_for_execution(
                    plan_id, step_id, token, agent_class, user_id, autonomy_level
                )
                self.autopilot.on_token_validation(agent_id, plan_id, step_id, token_valid)
                
                if not token_valid:
                    return {
                        "decision": DecisionType.DENY,
                        "obligations": [{"type": "reauthenticate", "reason": "Invalid step token"}],
                        "trust_level": trust_level,
                        "effective_autonomy": effective_autonomy,
                    }
            
            # Check step consent
            from consent_manager import is_step_approved
            if not is_step_approved(plan_id, step_id):
                self.autopilot.on_consent_decision(agent_id, plan_id, False)
                return {
                    "decision": DecisionType.DENY,
                    "obligations": [{"type": "consent_required", "reason": "Step not approved"}],
                    "trust_level": trust_level,
                    "effective_autonomy": effective_autonomy,
                }
            
            # Check PEP enforcement
            from pep_framework import PEPRequest, PEPType, enforce_pep
            
            # Determine PEP type from action
            pep_type = self._map_action_to_pep(action)
            if pep_type:
                pep_request = PEPRequest(
                    pep_type=pep_type,
                    token=token or "",
                    plan_id=plan_id,
                    step_id=step_id,
                    agent_class=agent_class,
                    user_id=user_id,
                    autonomy_level=autonomy_level,
                    action=action,
                    resource=resource,
                    metadata={"intent": intent},
                )
                pep_response = enforce_pep(pep_request)
                
                if not pep_response.success:
                    self.autopilot.on_policy_violation(agent_id, plan_id, step_id, {
                        "action": action,
                        "resource": resource,
                        "error": pep_response.error,
                    })
                    return {
                        "decision": DecisionType.DENY,
                        "obligations": [{"type": "policy_violation", "reason": pep_response.error}],
                        "trust_level": trust_level,
                        "effective_autonomy": effective_autonomy,
                    }
            
            # Success
            self.autopilot.on_step_success(agent_id, plan_id, step_id, {
                "action": action,
                "resource": resource,
            })
            
            return {
                "decision": DecisionType.PERMIT,
                "advice": [{"type": "token_valid", "valid": True}],
                "trust_level": trust_level,
                "effective_autonomy": effective_autonomy,
            }
        
        # Plan-level decision (no step context)
        # Check if plan is approved
        from consent_manager import is_plan_approved
        if plan_id and not is_plan_approved(plan_id):
            return {
                "decision": DecisionType.DENY,
                "obligations": [{"type": "consent_required", "reason": "Plan not approved"}],
                "trust_level": trust_level,
                "effective_autonomy": effective_autonomy,
            }
        
        # Allow plan-level operations
        return {
            "decision": DecisionType.PERMIT,
            "trust_level": trust_level,
            "effective_autonomy": effective_autonomy,
        }
    
    def _map_action_to_pep(self, action: str) -> Optional[PEPType]:
        """Map action to PEP type."""
        if action.startswith("file_"):
            return PEPType.FS
        elif action.startswith("shell_") or action.startswith("vm_"):
            return PEPType.EXEC
        elif action.startswith("http_") or action.startswith("tcp_") or action.startswith("dns_"):
            return PEPType.NET
        elif action.startswith("mcp_"):
            return PEPType.MCP
        return None


class SPIFFEIdentityProvider:
    """SPIFFE workload identity provider for agents."""
    
    def __init__(self, trust_domain: str = "guardrail.example.com"):
        self.trust_domain = trust_domain
        self.identities: Dict[str, Dict] = {}
        self.lock = Lock()
    
    def register_agent(self, agent_id: str, agent_class: str, user_id: str, autonomy_level: int) -> str:
        """Register an agent and return its SPIFFE ID."""
        spiffe_id = f"spiffe://{self.trust_domain}/agent/{agent_class}/{agent_id}"
        
        with self.lock:
            self.identities[agent_id] = {
                "spiffe_id": spiffe_id,
                "agent_class": agent_class,
                "user_id": user_id,
                "autonomy_level": autonomy_level,
                "created_at": int(time.time()),
                "selectors": [
                    f"agent_class:{agent_class}",
                    f"user:{user_id}",
                    f"autonomy_level:{autonomy_level}",
                ],
            }
        
        return spiffe_id
    
    def get_identity(self, agent_id: str) -> Optional[Dict]:
        """Get agent identity."""
        return self.identities.get(agent_id)
    
    def verify_spiffe_id(self, spiffe_id: str) -> Optional[Dict]:
        """Verify a SPIFFE ID and return identity info."""
        for agent_id, info in self.identities.items():
            if info["spiffe_id"] == spiffe_id:
                return {"agent_id": agent_id, **info}
        return None
    
    def create_x509_svid(self, agent_id: str) -> Dict[str, str]:
        """Create a mock X.509 SVID for an agent."""
        identity = self.identities.get(agent_id)
        if not identity:
            return {}
        
        # In production, this would generate actual X.509 certificates
        return {
            "spiffe_id": identity["spiffe_id"],
            "certificate": "MOCK_CERTIFICATE_PEM",
            "private_key": "MOCK_PRIVATE_KEY_PEM",
            "expires_at": str(int(time.time()) + 3600),
        }
    
    def create_jwt_svid(self, agent_id: str, audience: List[str]) -> str:
        """Create a mock JWT SVID for an agent."""
        identity = self.identities.get(agent_id)
        if not identity:
            return ""
        
        # In production, this would generate actual JWT-SVID
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": f"https://{self.trust_domain}",
            "sub": identity["spiffe_id"],
            "aud": audience,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "agent_class": identity["agent_class"],
            "user_id": identity["user_id"],
        }
        
        # Mock encoding
        import base64
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(b"MOCK_SIGNATURE").decode().rstrip("=")
        
        return f"{header_b64}.{payload_b64}.{signature}"


class IDJAGBroker:
    """ID-JAG (Identity-Aware Governance) Enterprise Broker."""
    
    def __init__(self, spiffe_provider: SPIFFEIdentityProvider):
        self.spiffe_provider = spiffe_provider
        self.delegations: Dict[str, Dict] = {}
        self.lock = Lock()
    
    def create_delegation(
        self,
        delegator_id: str,
        delegatee_id: str,
        scope: List[str],
        constraints: Dict[str, Any],
        expires_at: int,
    ) -> str:
        """Create a delegation from delegator to delegatee."""
        delegation_id = str(uuid.uuid4())
        
        with self.lock:
            self.delegations[delegation_id] = {
                "delegation_id": delegation_id,
                "delegator_id": delegator_id,
                "delegatee_id": delegatee_id,
                "scope": scope,  # e.g., ["file_read", "http_get"]
                "constraints": constraints,  # e.g., {"max_autonomy": 2, "time_window": "09:00-17:00"}
                "created_at": int(time.time()),
                "expires_at": expires_at,
                "active": True,
            }
        
        return delegation_id
    
    def validate_delegation(self, delegation_id: str, action: str, resource: str) -> bool:
        """Validate if a delegation allows an action."""
        with self.lock:
            delegation = self.delegations.get(delegation_id)
            if not delegation or not delegation["active"]:
                return False
            
            if int(time.time()) > delegation["expires_at"]:
                delegation["active"] = False
                return False
            
            # Check scope
            if action not in delegation["scope"]:
                return False
            
            # Check constraints
            constraints = delegation["constraints"]
            if "time_window" in constraints:
                # Simplified time window check
                pass
            
            if "max_autonomy" in constraints:
                # Would check delegatee's autonomy level
                pass
            
            return True
    
    def revoke_delegation(self, delegation_id: str) -> bool:
        """Revoke a delegation."""
        with self.lock:
            if delegation_id in self.delegations:
                self.delegations[delegation_id]["active"] = False
                return True
            return False
    
    def get_delegations_for_agent(self, agent_id: str) -> List[Dict]:
        """Get all delegations for an agent."""
        with self.lock:
            return [
                d for d in self.delegations.values()
                if d["delegatee_id"] == agent_id or d["delegator_id"] == agent_id
            ]


# Global instances
_authzen_engine: Optional[AuthZENDecisionEngine] = None
_spiffe_provider: Optional[SPIFFEIdentityProvider] = None
_idjag_broker: Optional[IDJAGBroker] = None


def get_authzen_engine() -> AuthZENDecisionEngine:
    """Get the global AuthZEN decision engine."""
    global _authzen_engine
    if _authzen_engine is None:
        _authzen_engine = AuthZENDecisionEngine()
    return _authzen_engine


def get_spiffe_provider() -> SPIFFEIdentityProvider:
    """Get the global SPIFFE identity provider."""
    global _spiffe_provider
    if _spiffe_provider is None:
        _spiffe_provider = SPIFFEIdentityProvider()
    return _spiffe_provider


def get_idjag_broker() -> IDJAGBroker:
    """Get the global ID-JAG broker."""
    global _idjag_broker
    if _idjag_broker is None:
        _idjag_broker = IDJAGBroker(get_spiffe_provider())
    return _idjag_broker


def evaluate_authzen(request: AuthZENDecisionRequest) -> AuthZENDecisionResponse:
    """Convenience function for AuthZEN evaluation."""
    return get_authzen_engine().evaluate(request)


def register_agent_identity(
    agent_id: str,
    agent_class: str,
    user_id: str,
    autonomy_level: int
) -> str:
    """Register agent and get SPIFFE ID."""
    return get_spiffe_provider().register_agent(agent_id, agent_class, user_id, autonomy_level)


def create_delegation(
    delegator_id: str,
    delegatee_id: str,
    scope: List[str],
    constraints: Dict[str, Any],
    expires_at: int,
) -> str:
    """Create an ID-JAG delegation."""
    return get_idjag_broker().create_delegation(delegator_id, delegatee_id, scope, constraints, expires_at)


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Initialize components
    spiffe = get_spiffe_provider()
    idjag = get_idjag_broker()
    authzen = get_authzen_engine()
    
    # Register agent
    agent_id = "agent_coding_001"
    spiffe_id = spiffe.register_agent(agent_id, "coding", "user123", 2)
    print(f"Agent SPIFFE ID: {spiffe_id}")
    
    # Create delegation
    delegation_id = idjag.create_delegation(
        delegator_id="admin_001",
        delegatee_id=agent_id,
        scope=["file_read", "file_write", "http_get"],
        constraints={"max_autonomy": 2, "time_window": "09:00-17:00"},
        expires_at=int(time.time()) + 86400,
    )
    print(f"Delegation created: {delegation_id}")
    
    # Create AuthZEN request
    from authzen import AuthZENSubject, AuthZENResource, AuthZENAction, AuthZENContext
    
    subject = AuthZENSubject(
        subject_id=agent_id,
        subject_type=SubjectType.AGENT,
        spiffe_id=spiffe_id,
        attributes={"user_id": "user123", "agent_class": "coding", "autonomy_level": 2},
    )
    
    resource = AuthZENResource(
        resource_id="/etc/config.yaml",
        resource_type="file",
        attributes={"path": "/etc/config.yaml", "owner": "root"},
    )
    
    action = AuthZENAction(
        action_id="file_write",
        action_type="write",
        attributes={},
    )
    
    context = AuthZENContext(
        request_id=str(uuid.uuid4()),
        timestamp=int(time.time() * 1000),
        environment={
            "plan_id": "plan_001",
            "step_id": "step_001",
            "token": "mock_token",
            "intent": "Write configuration file",
        },
    )
    
    request = AuthZENDecisionRequest(
        subject=subject,
        resource=resource,
        action=action,
        context=context,
    )
    
    # Evaluate
    response = authzen.evaluate(request)
    print(f"AuthZEN Decision: {response.decision.value}")
    print(f"Metadata: {response.metadata}")