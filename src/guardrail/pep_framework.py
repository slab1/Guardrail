"""PEP (Policy Enforcement Point) Framework Base Classes."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from guardrail.token_service import TokenPayload


class PEPType(Enum):
    """Types of PEPs."""
    MCP = "mcp"
    FS = "fs"           # File System (LSFS)
    EXEC = "exec"       # Execution (Firecracker)
    NET = "net"         # Network


@dataclass
class PEPRequest:
    """Base request for all PEPs."""
    pep_type: PEPType
    token: str                    # Step token for authorization
    plan_id: str
    step_id: str
    agent_class: str
    user_id: str
    autonomy_level: int
    action: str                   # Specific action being requested
    resource: str                 # Resource being accessed
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PEPResponse:
    """Base response from all PEPs."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    rollback_info: Optional[Dict[str, Any]] = None  # For reversible actions


class BasePEP(ABC):
    """Abstract base class for all Policy Enforcement Points."""
    
    def __init__(self, pep_type: PEPType):
        self.pep_type = pep_type
        self.allowed_actions: Set[str] = set()
        self.action_categories: Dict[str, str] = {}  # action -> category
    
    @abstractmethod
    def enforce(self, request: PEPRequest) -> PEPResponse:
        """Enforce policy for a request. Must be implemented by subclasses."""
        pass
    
    def validate_token(self, request: PEPRequest) -> bool:
        """Validate the step token."""
        from guardrail.plan_compiler.enhanced_plan_compiler import validate_step_token_for_execution
        return validate_step_token_for_execution(
            request.plan_id,
            request.step_id,
            request.token,
            request.agent_class,
            request.user_id,
            request.autonomy_level
        )
    
    def check_action_allowed(self, action: str) -> bool:
        """Check if action is allowed by this PEP."""
        return action in self.allowed_actions
    
    def get_category(self, action: str) -> str:
        """Get category for an action."""
        return self.action_categories.get(action, "unknown")
    
    def create_denied_response(self, request: PEPRequest, reason: str) -> PEPResponse:
        """Create a standard denied response."""
        return PEPResponse(
            success=False,
            error=reason,
            details={
                "pep_type": self.pep_type.value,
                "action": request.action,
                "resource": request.resource,
                "plan_id": request.plan_id,
                "step_id": request.step_id,
            }
        )
    
    def create_approved_response(self, request: PEPRequest, result: Any, rollback_info: Optional[Dict] = None) -> PEPResponse:
        """Create a standard approved response."""
        return PEPResponse(
            success=True,
            result=result,
            details={
                "pep_type": self.pep_type.value,
                "action": request.action,
                "resource": request.resource,
                "plan_id": request.plan_id,
                "step_id": request.step_id,
            },
            rollback_info=rollback_info
        )


class PEPRegistry:
    """Registry for all PEPs."""
    
    def __init__(self):
        self.peps: Dict[PEPType, BasePEP] = {}
    
    def register(self, pep: BasePEP):
        """Register a PEP."""
        self.peps[pep.pep_type] = pep
    
    def get_pep(self, pep_type: PEPType) -> Optional[BasePEP]:
        """Get a PEP by type."""
        return self.peps.get(pep_type)
    
    def enforce(self, request: PEPRequest) -> PEPResponse:
        """Route request to appropriate PEP."""
        pep = self.peps.get(request.pep_type)
        if not pep:
            return PEPResponse(
                success=False,
                error=f"No PEP registered for type {request.pep_type.value}"
            )
        return pep.enforce(request)


# Global PEP registry
_pep_registry: Optional[PEPRegistry] = None


def get_pep_registry() -> PEPRegistry:
    """Get the global PEP registry."""
    global _pep_registry
    if _pep_registry is None:
        _pep_registry = PEPRegistry()
    return _pep_registry


def register_pep(pep: BasePEP):
    """Register a PEP globally."""
    get_pep_registry().register(pep)


def enforce_pep(request: PEPRequest) -> PEPResponse:
    """Enforce a PEP request globally."""
    return get_pep_registry().enforce(request)