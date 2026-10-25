"""Guardrail Agent - High-level API for executing plans with Guardrail protection."""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from guardrail.plan_compiler.enhanced_plan_compiler import (
    compile_and_validate_plan, ValidatedPlan, ValidatedStep, validate_step_token_for_execution
)
from guardrail.token_service import create_plan_token, create_step_token
from guardrail.consent_manager import ConsentManager, ConsentDecision, request_consent_interactive
from guardrail.pep_framework import PEPRequest, PEPType, enforce_pep
from guardrail.pep_fs import create_pep_fs
from guardrail.pep_exec import create_pep_exec
from guardrail.pep_net import create_pep_net
from guardrail.causal_audit import AuditEventType, create_causal_label, log_audit_event
from guardrail.autopilot import AutopilotController
from guardrail.monitoring import get_metrics, MetricLabels


@dataclass
class StepResult:
    """Result of executing a single step."""
    step_id: str
    action: str
    resource: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class AgentResult:
    """Result of executing a full plan."""
    plan_id: str
    plan_description: str
    consent_given: bool
    step_results: List[StepResult] = field(default_factory=list)
    error: Optional[str] = None
    total_duration_ms: float = 0.0


class GuardrailAgent:
    """
    High-level Guardrail agent for executing plans with full policy enforcement.
    
    This agent integrates all Guardrail components:
    - Plan compilation and validation
    - Token generation and validation
    - Consent management
    - PEP enforcement (FS, Exec, Net)
    - Causal audit logging
    - Autopilot trust scoring
    - Metrics collection
    """
    
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        lsfs_root: str = "/tmp/guardrail_lsfs",
        firecracker_root: str = "/tmp/guardrail_firecracker",
        enable_audit: bool = True,
        enable_autopilot: bool = True,
        enable_metrics: bool = True,
    ):
        """
        Initialize a Guardrail agent.
        
        Args:
            agent_class: Agent class for policy enforcement (coding, data_analysis, etc.)
            user_id: User identifier
            autonomy_level: Autonomy level (0=L0, 1=L1, 2=L2, 3=L3)
            lsfs_root: Root directory for LSFS file system
            firecracker_root: Root directory for Firecracker VMs
            enable_audit: Enable causal audit logging
            enable_autopilot: Enable autopilot trust scoring
            enable_metrics: Enable metrics collection
        """
        self.agent_class = agent_class
        self.user_id = user_id
        self.autonomy_level = autonomy_level
        self.enable_audit = enable_audit
        self.enable_autopilot = enable_autopilot
        self.enable_metrics = enable_metrics
        
        # Initialize components
        self.consent_manager = ConsentManager()
        self.autopilot = AutopilotController() if enable_autopilot else None
        self.metrics = get_metrics() if enable_metrics else None
        
        # Initialize PEPs
        self.pep_fs = create_pep_fs(lsfs_root)
        self.pep_exec = create_pep_exec(firecracker_root)
        self.pep_net = create_pep_net()
        
        # Audit logger
        self.audit_logger = None
        if enable_audit:
            from guardrail.causal_audit import CausalAuditLogger
            self.audit_logger = CausalAuditLogger("/tmp/guardrail_audit.log")
        
        # Active plan tracking
        self.current_plan: Optional[ValidatedPlan] = None
        self.current_plan_id: Optional[str] = None
    
    def run(
        self,
        intent: str,
        plan_id: Optional[str] = None,
        require_consent: bool = True,
    ) -> AgentResult:
        """
        Execute a plan from natural language intent.
        
        Args:
            intent: Natural language description of the task
            plan_id: Optional plan identifier (generated if not provided)
            require_consent: Whether to require human consent
            
        Returns:
            AgentResult with execution details
        """
        import time
        start_time = time.time()
        
        # Compile and validate plan
        vplan = compile_and_validate_plan(
            intent=intent,
            plan_id=plan_id,
            agent_class=self.agent_class,
            user_id=self.user_id,
            autonomy_level=self.autonomy_level,
        )
        
        self.current_plan = vplan
        self.current_plan_id = vplan.id
        
        # Initialize result
        result = AgentResult(
            plan_id=vplan.id,
            plan_description=vplan.description,
            consent_given=False,
        )
        
        # Check for validation errors
        if vplan.validation_errors:
            result.error = f"Plan validation failed: {vplan.validation_errors}"
            return result
        
        # Request consent if required
        if require_consent:
            decision = request_consent_interactive(vplan, risk_level="medium")
            result.consent_given = decision.approved
            if not decision.approved:
                result.error = "Plan not approved by user"
                if self.enable_autopilot and self.autopilot:
                    self.autopilot.on_consent_decision(self.user_id, vplan.id, False)
                return result
            
            if self.enable_autopilot and self.autopilot:
                self.autopilot.on_consent_decision(self.user_id, vplan.id, True)
        
        # Execute each step
        for step in vplan.steps:
            step_result = self._execute_step(vplan, step)
            result.step_results.append(step_result)
            
            if not step_result.success:
                result.error = f"Step {step.step_id} failed: {step_result.error}"
                break
        
        result.total_duration_ms = (time.time() - start_time) * 1000
        
        # Record metrics
        if self.enable_metrics and self.metrics:
            labels = MetricLabels(
                agent_id=self.user_id,
                agent_class=self.agent_class,
                plan_id=vplan.id,
                step_id="",
                autonomy_level=str(self.autonomy_level),
                trust_level=self._get_trust_level_name(),
            )
            self.metrics.record_plan_executed(labels, result.total_duration_ms / 1000)
        
        # Record autopilot success
        if self.enable_autopilot and self.autopilot and not result.error:
            self.autopilot.on_step_success(self.user_id, vplan.id, "complete")
        
        return result
    
    def _execute_step(self, vplan: ValidatedPlan, step: ValidatedStep) -> StepResult:
        """Execute a single plan step with full Guardrail enforcement."""
        import time
        start_time = time.time()
        
        # Validate step token
        step_token = vplan.step_tokens.get(step.id)
        if not step_token:
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=False,
                error="No step token available",
            )
        
        token_valid = validate_step_token_for_execution(
            vplan.id, step.id, step_token,
            self.agent_class, self.user_id, self.autonomy_level
        )
        
        if not token_valid:
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=False,
                error="Invalid step token",
            )
        
        # Record token validation
        if self.enable_autopilot and self.autopilot:
            self.autopilot.on_token_validation(self.user_id, vplan.id, step.id, True)
        
        if self.enable_metrics and self.metrics:
            labels = MetricLabels(
                agent_id=self.user_id,
                agent_class=self.agent_class,
                plan_id=vplan.id,
                step_id=step.id,
                autonomy_level=str(self.autonomy_level),
                trust_level=self._get_trust_level_name(),
            )
            self.metrics.record_token_validation(labels, True)
        
        # Check step consent
        if not self.consent_manager.is_step_approved(vplan.id, step.id):
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=False,
                error="Step not approved by consent",
            )
        
        # Determine PEP type and enforce
        pep_type = self._map_action_to_pep(step.action_type)
        if not pep_type:
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=False,
                error=f"No PEP for action: {step.action_type}",
            )
        
        # Build PEP request
        pep_request = PEPRequest(
            pep_type=pep_type,
            token=step_token,
            plan_id=vplan.id,
            step_id=step.id,
            agent_class=self.agent_class,
            user_id=self.user_id,
            autonomy_level=self.autonomy_level,
            action=step.action_type,
            resource=step.resource or "",
            metadata=self._build_pep_metadata(step),
        )
        
        # Record audit event before execution
        if self.enable_audit and self.audit_logger:
            causal_label = create_causal_label(
                plan_id=vplan.id,
                step_id=step.id,
                intent=step.description,
                agent_class=self.agent_class,
                user_id=self.user_id,
                autonomy_level=self.autonomy_level,
            )
            log_audit_event(
                AuditEventType.CAPABILITY_CHECK,
                causal_label,
                syscall=f"pep_enforce:{step.action_type}",
                args={"resource": step.resource},
                result="pending",
            )
        
        # Execute via PEP
        pep_response = enforce_pep(pep_request)
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Record metrics
        if self.enable_metrics and self.metrics:
            labels = MetricLabels(
                agent_id=self.user_id,
                agent_class=self.agent_class,
                plan_id=vplan.id,
                step_id=step.id,
                autonomy_level=str(self.autonomy_level),
                trust_level=self._get_trust_level_name(),
            )
            self.metrics.record_step(labels, step.action_type, "success" if pep_response.success else "failure", duration_ms / 1000)
            self.metrics.record_pep_enforcement(pep_type.value, step.action_type, "allow" if pep_response.success else "deny", duration_ms / 1000)
        
        # Record audit event after execution
        if self.enable_audit and self.audit_logger:
            causal_label = create_causal_label(
                plan_id=vplan.id,
                step_id=step.id,
                intent=step.description,
                agent_class=self.agent_class,
                user_id=self.user_id,
                autonomy_level=self.autonomy_level,
            )
            log_audit_event(
                AuditEventType.CAPABILITY_CHECK,
                causal_label,
                syscall=f"pep_enforce:{step.action_type}",
                args={"resource": step.resource},
                result=pep_response.success,
                duration_ns=int(duration_ms * 1_000_000),
            )
        
        # Record autopilot
        if self.enable_autopilot and self.autopilot:
            if pep_response.success:
                self.autopilot.on_step_success(self.user_id, vplan.id, step.id)
            else:
                self.autopilot.on_policy_violation(self.user_id, vplan.id, step.id, {
                    "action": step.action_type,
                    "resource": step.resource,
                    "error": pep_response.error,
                })
        
        if pep_response.success:
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=True,
                result=pep_response.result,
                duration_ms=duration_ms,
            )
        else:
            return StepResult(
                step_id=step.id,
                action=step.action_type,
                resource=step.resource or "",
                success=False,
                error=pep_response.error,
                duration_ms=duration_ms,
            )
    
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
    
    def _build_pep_metadata(self, step: ValidatedStep) -> Dict[str, Any]:
        """Build PEP metadata from step."""
        metadata = {"intent": step.description}
        
        # Add step-specific metadata
        if step.action_type in ("file_write", "file_read", "file_delete", "file_list"):
            metadata["path"] = step.resource
        elif step.action_type.startswith("http_"):
            metadata["url"] = step.resource
            metadata["method"] = step.action_type.upper().replace("HTTP_", "")
        elif step.action_type.startswith("shell_"):
            metadata["command"] = step.resource
        elif step.action_type.startswith("vm_"):
            metadata["vm_id"] = step.resource
        
        return metadata
    
    def _get_trust_level_name(self) -> str:
        """Get trust level name for metrics."""
        if self.enable_autopilot and self.autopilot:
            status = self.autopilot.get_status(self.user_id)
            return status.get("trust_level", "LOCKED")
        return "LOCKED"
    
    def create_plan(self, intent: str, plan_id: Optional[str] = None) -> ValidatedPlan:
        """Create and validate a plan without executing."""
        return compile_and_validate_plan(
            intent=intent,
            plan_id=plan_id,
            agent_class=self.agent_class,
            user_id=self.user_id,
            autonomy_level=self.autonomy_level,
        )
    
    def request_consent(self, plan: ValidatedPlan, risk_level: str = "medium") -> ConsentDecision:
        """Request consent for a plan."""
        return request_consent_interactive(plan, risk_level)
    
    def get_autopilot_status(self) -> Dict[str, Any]:
        """Get autopilot status for this agent."""
        if self.enable_autopilot and self.autopilot:
            return self.autopilot.get_status(self.user_id)
        return {"status": "autopilot_disabled"}
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        if self.enable_metrics and self.metrics:
            return {"status": "metrics_enabled"}
        return {"status": "metrics_disabled"}