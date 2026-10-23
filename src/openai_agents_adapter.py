"""Adapter for OpenAI Agents SDK integration with Guardrail."""
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from plan_compiler.enhanced_plan_compiler import (
    ValidatedPlan, ValidatedStep, compile_and_validate_plan, validate_step_token_for_execution
)
from token_service import validate_plan_token, validate_step_token
from consent_manager import is_plan_approved, is_step_approved


@dataclass
class OpenAIAgentState:
    """State for Guardrail-enabled OpenAI Agent."""
    plan: Optional[ValidatedPlan] = None
    current_step_index: int = 0
    step_results: List[Dict[str, Any]] = None
    consent_given: bool = False
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.step_results is None:
            self.step_results = []


class OpenAIAgentsAdapter:
    """Adapter to integrate Guardrail with OpenAI Agents SDK."""
    
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        tool_executor: Optional[Callable[[ValidatedStep], Any]] = None
    ):
        self.agent_class = agent_class
        self.user_id = user_id
        self.autonomy_level = autonomy_level
        self.tool_executor = tool_executor or self._default_executor
    
    def _default_executor(self, step: ValidatedStep) -> Dict[str, Any]:
        """Default tool executor that returns mock results."""
        return {
            "status": "executed",
            "step_id": step.id,
            "action": step.action_type,
            "resource": step.resource,
            "result": f"Mock execution of {step.action_type} on {step.resource}",
        }
    
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
    
    def run_agent(self, intent: str) -> OpenAIAgentState:
        """Run the complete agent workflow."""
        state = OpenAIAgentState()
        
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
    
    def create_agent_tools(self) -> List[Dict[str, Any]]:
        """Create tool definitions for OpenAI Agents SDK."""
        # This would generate function calling definitions for the agent
        # For now, return a placeholder
        return [
            {
                "type": "function",
                "function": {
                    "name": "guardrail_execute_plan",
                    "description": "Execute a Guardrail-validated plan",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "intent": {"type": "string"},
                        },
                        "required": ["intent"],
                    },
                },
            }
        ]


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    adapter = OpenAIAgentsAdapter(
        agent_class="coding",
        user_id="user123",
        autonomy_level=2
    )
    
    intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    result = adapter.run_agent(intent)
    
    print(f"Plan: {result.plan.id if result.plan else 'None'}")
    print(f"Consent given: {result.consent_given}")
    print(f"Steps executed: {len(result.step_results)}")
    print(f"Error: {result.error}")
    for r in result.step_results:
        print(f"  - {r}")