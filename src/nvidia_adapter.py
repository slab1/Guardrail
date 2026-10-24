"""Adapter for NVIDIA Nemotron / NVIDIA AI Enterprise integration with Guardrail."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from guardrail.plan_compiler.enhanced_plan_compiler import (
    ValidatedPlan, ValidatedStep, compile_and_validate_plan, validate_step_token_for_execution
)
from guardrail.token_service import validate_plan_token, validate_step_token
from guardrail.consent_manager import is_plan_approved, is_step_approved
from guardrail.tools.executor import RealToolExecutor, create_tool_executor


@dataclass
class NvidiaAgentState:
    """State for Guardrail-enabled NVIDIA agent."""
    plan: Optional[ValidatedPlan] = None
    current_step_index: int = 0
    step_results: List[Dict[str, Any]] = None
    consent_given: bool = False
    error: Optional[str] = None
    model_name: str = "nvidia/nemotron-3-ultra-550b-a55b"
    
    def __post_init__(self):
        if self.step_results is None:
            self.step_results = []


class NvidiaAdapter:
    """Adapter to integrate Guardrail with NVIDIA Nemotron models and NVIDIA AI Enterprise stack."""
    
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        tool_executor: Optional[Callable] = None,
        model_name: str = "nvidia/nemotron-3-ultra-550b-a55b",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        allowed_paths: List[str] = None,
        command_timeout: int = 30
    ):
        self.agent_class = agent_class
        self.user_id = user_id
        self.autonomy_level = autonomy_level
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url
        
        # Create real tool executor if not provided
        if tool_executor is None:
            self.executor = RealToolExecutor(
                allowed_paths=allowed_paths,
                command_timeout=command_timeout
            )
            self.tool_executor = create_tool_executor("generic", self.executor)
        else:
            self.tool_executor = tool_executor
    
    def create_plan(self, intent: str) -> ValidatedPlan:
        """Compile and validate a plan."""
        return compile_and_validate_plan(
            intent=intent,
            agent_class=self.agent_class,
            user_id=self.user_id,
            autonomy_level=self.autonomy_level,
        )
    
    def check_consent(self, plan: ValidatedPlan) -> bool:
        """Check if plan has consent."""
        return is_plan_approved(plan.id)
    
    def validate_step_token(self, plan: ValidatedPlan, step: ValidatedStep) -> bool:
        """Validate a step token."""
        step_token = plan.step_tokens.get(step.id)
        if not step_token:
            return False
        return validate_step_token_for_execution(
            plan.id,
            step.id,
            step_token,
            self.agent_class,
            self.user_id,
            self.autonomy_level
        )
    
    def execute_step(self, plan: ValidatedPlan, step: ValidatedStep) -> Dict[str, Any]:
        """Execute a single step."""
        return self.tool_executor(step)
    
    def run_agent(self, intent: str) -> NvidiaAgentState:
        """Run the complete agent workflow."""
        state = NvidiaAgentState(model_name=self.model_name)
        
        # Create plan
        state.plan = self.create_plan(intent)
        if state.plan.validation_errors:
            state.error = f"Plan validation failed: {state.plan.validation_errors}"
            return state
        
        # Check consent
        if not self.check_consent(state.plan):
            state.error = "Plan not approved"
            return state
        
        state.consent_given = True
        
        # Execute steps
        for i, step in enumerate(state.plan.steps):
            state.current_step_index = i
            
            # Check step consent
            if not is_step_approved(state.plan.id, step.id):
                state.error = f"Step {step.id} not approved"
                break
            
            # Validate token
            if not self.validate_step_token(state.plan, step):
                state.error = f"Invalid token for step {step.id}"
                break
            
            # Execute
            try:
                result = self.execute_step(state.plan, step)
                state.step_results.append(result)
            except Exception as e:
                state.error = f"Step execution failed: {str(e)}"
                break
        
        return state
    
    def create_nvidia_function_calling_tools(self) -> List[Dict[str, Any]]:
        """Create function calling definitions compatible with NVIDIA Nemotron function calling."""
        return [
            {
                "name": "guardrail_execute_plan",
                "description": "Execute a Guardrail-validated plan with per-step authorization",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "intent": {
                            "type": "string",
                            "description": "Natural language description of the task to execute"
                        },
                        "agent_class": {
                            "type": "string",
                            "description": "Agent class for policy enforcement (coding, data_analysis, travel_booking, email_comms, file_organizer)",
                            "enum": ["coding", "data_analysis", "travel_booking", "email_comms", "file_organizer"]
                        },
                        "autonomy_level": {
                            "type": "integer",
                            "description": "Autonomy level (0=Locked, 1=Protected, 2=Unrestricted, 3=Full)",
                            "minimum": 0,
                            "maximum": 3
                        }
                    },
                    "required": ["intent"],
                },
            },
            {
                "name": "guardrail_check_consent",
                "description": "Check if a plan has been approved by the user",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "plan_id": {"type": "string"},
                    },
                    "required": ["plan_id"],
                },
            },
            {
                "name": "guardrail_validate_token",
                "description": "Validate a step token for execution",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "plan_id": {"type": "string"},
                        "step_id": {"type": "string"},
                        "token": {"type": "string"},
                    },
                    "required": ["plan_id", "step_id", "token"],
                },
            },
        ]
    
    def get_model_config(self) -> Dict[str, Any]:
        """Get model configuration for NVIDIA Nemotron."""
        return {
            "model": self.model_name,
            "temperature": 0.1,
            "max_tokens": 4096,
            "top_p": 0.9,
            "functions": self.create_nvidia_function_calling_tools(),
            "function_call": "auto",
        }


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    adapter = NvidiaAdapter(
        agent_class="coding",
        user_id="user123",
        autonomy_level=2,
        model_name="nvidia/nemotron-3-ultra-550b-a55b"
    )
    
    intent = "Create a new file called config.yaml in /tmp/ and then run a validation script on it."
    result = adapter.run_agent(intent)
    
    print(f"Model: {result.model_name}")
    print(f"Plan: {result.plan.id if result.plan else 'None'}")
    print(f"Consent given: {result.consent_given}")
    print(f"Steps executed: {len(result.step_results)}")
    print(f"Error: {result.error}")
    for r in result.step_results:
        print(f"  - {r}")
    
    print("\nNVIDIA Function Calling Tools:")
    for tool in adapter.create_nvidia_function_calling_tools():
        print(f"  - {tool['name']}: {tool['description']}")