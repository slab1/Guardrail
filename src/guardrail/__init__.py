"""Guardrail - Intelligent OS Policy Engine for AI Agents."""

from .agent import GuardrailAgent, AgentResult, StepResult
from .plan_compiler import compile_and_validate_plan, ValidatedPlan, ValidatedStep
from .token_service import (
    create_plan_token, create_step_token,
    validate_plan_token, validate_step_token,
    validate_step_token_for_execution
)
from .consent_manager import (
    ConsentManager, ConsentDecision, ConsentStatus,
    request_consent_interactive
)
from .pep_framework import PEPRequest, PEPResponse, PEPType, enforce_pep
from .pep_fs import create_pep_fs
from .pep_exec import create_pep_exec
from .pep_net import create_pep_net
from .causal_audit import (
    CausalAuditLogger, AuditEventType, CausalLabel,
    create_causal_label, log_audit_event
)
from .autopilot import AutopilotController, TrustLevel
from .authzen import (
    AuthZENDecisionEngine, AuthZENSubject, AuthZENResource, AuthZENAction,
    AuthZENContext, AuthZENDecisionRequest, DecisionType, SubjectType,
    SPIFFEIdentityProvider, IDJAGBroker,
    get_spiffe_provider, get_idjag_broker
)
from .monitoring import MetricsRegistry, get_metrics, init_monitoring
from .compliance import (
    ComplianceReporter, ComplianceFramework, ControlStatus,
    generate_compliance_report
)
from .scaling import (
    ClusterManager, ServiceInstance, Tenant,
    LoadBalancingAlgorithm, get_cluster_manager, init_cluster
)

__version__ = "1.0.0"

__all__ = [
    # Agent
    "GuardrailAgent", "AgentResult", "StepResult",
    # Plan Compiler
    "compile_and_validate_plan", "ValidatedPlan", "ValidatedStep",
    # Token Service
    "create_plan_token", "create_step_token",
    "validate_plan_token", "validate_step_token",
    "validate_step_token_for_execution",
    # Consent
    "ConsentManager", "ConsentDecision", "ConsentStatus",
    "request_consent_interactive",
    # PEP Framework
    "PEPRequest", "PEPResponse", "PEPType", "enforce_pep",
    "create_pep_fs", "create_pep_exec", "create_pep_net",
    # Causal Audit
    "CausalAuditLogger", "AuditEventType", "CausalLabel",
    "create_causal_label", "log_audit_event",
    # Autopilot
    "AutopilotController", "TrustLevel",
    # AuthZEN
    "AuthZENDecisionEngine", "AuthZENSubject", "AuthZENResource", "AuthZENAction",
    "AuthZENContext", "AuthZENDecisionRequest", "DecisionType", "SubjectType",
    "SPIFFEIdentityProvider", "IDJAGBroker",
    "get_spiffe_provider", "get_idjag_broker",
    # Monitoring
    "MetricsRegistry", "get_metrics", "init_monitoring",
    # Compliance
    "ComplianceReporter", "ComplianceFramework", "ControlStatus",
    "generate_compliance_report",
    # Scaling
    "ClusterManager", "ServiceInstance", "Tenant",
    "LoadBalancingAlgorithm", "get_cluster_manager", "init_cluster",
]

# Convenience: top-level imports
from . import plan_compiler
from . import token_service
from . import consent_manager
from . import pep_framework
from . import pep_fs
from . import pep_exec
from . import pep_net
from . import causal_audit
from . import autopilot
from . import authzen
from . import monitoring
from . import compliance
from . import scaling