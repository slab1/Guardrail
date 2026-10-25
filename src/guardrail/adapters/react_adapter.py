"""ReAct adapter for Guardrail integration."""
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from guardrail.plan_compiler.enhanced_plan_compiler import (
    ValidatedPlan, ValidatedStep, compile_and_validate_plan, validate_step_token_for_execution
)
from guardrail.token_service import validate_plan_token, validate_step_token
from guardrail.consent_manager import is_plan_approved, is_step_approved


@dataclass
class ReActState:
    """State for ReAct loop with Guardrail."""
    plan: Optional[ValidatedPlan] = None
    current_step_index: int = 0
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    thoughts: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    consent_given: bool = False
    error: Optional[str] = None
    finished: bool = False


class ReActAdapter:
    """Adapter to integrate Guardrail with ReAct (Reasoning + Acting) loops."""
    
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "user",
        autonomy_level: int = 1,
        tool_executor: Optional[Callable[[ValidatedStep], Any]] = None,
        llm_reasoner: Optional[Callable[[str, List[str], List[Dict]], str]] = None
    ):
        self.agent_class = agent_class
        self.user_id = user_id
        self.autonomy_level = autonomy_level
        self.tool_executor = tool_executor or self._default_executor
        self.llm_reasoner = llm_reasoner or self._default_reasoner
    
    def _default_executor(self, step: ValidatedStep) -> Dict[str, Any]:
        """Default tool executor that returns mock results."""
        return {
            "status": "executed",
            "step_id": step.id,
            "action": step.action_type,
            "resource": step.resource,
            "result": f"Mock execution of {step.action_type} on {step.resource}",
        }
    
    def _default_reasoner(self, intent: str, observations: List[str], actions: List[Dict]) -> str:
        """Default reasoning function (placeholder)."""
        return f"Reasoning about: {intent}. Observations: {observations}. Last action: {actions[-1] if actions else 'None'}"
    
    def initialize(self, intent: str) -> ReActState:
        """Initialize the ReAct state with a plan."""
        state = ReActState()
        state.plan = compile_and_validate_plan(
            intent=intent,
            agent_class=self.agent_class,
            user_id=self.user_id,
            autonomy_level=self.autonomy_level,
        )
        if state.plan.validation_errors:
            state.error = f"Plan validation failed: {state.plan.validation_errors}"
        return state
    
    def check_consent(self, state: ReActState) -> bool:
        """Check if plan has consent."""
        if not state.plan:
            return False
        return is_plan_approved(state.plan.id)
    
    def reason(self, state: ReActState) -> str:
        """Generate reasoning for the current step."""
        if not state.plan or state.current_step_index >= len(state.plan.steps):
            return "No more steps to execute"
        
        step = state.plan.steps[state.current_step_index]
        thought = self.llm_reasoner(
            state.plan.description,
            state.observations,
            state.actions
        )
        state.thoughts.append(thought)
        return thought
    
    def act(self, state: ReActState) -> Dict[str, Any]:
        """Execute the current step."""
        if not state.plan or state.error or state.finished:
            return {"status": "error", "message": state.error or "No plan or already finished"}
        
        if state.current_step_index >= len(state.plan.steps):
            state.finished = True
            return {"status": "complete", "message": "All steps executed"}
        
        step = state.plan.steps[state.current_step_index]
        
        # Check step consent
        if not is_step_approved(state.plan.id, step.id):
            state.error = f"Step {step.id} not approved"
            return {"status": "error", "message": state.error}
        
        # Validate token
        step_token = state.plan.step_tokens.get(step.id)
        if not step_token or not validate_step_token_for_execution(
            state.plan.id,
            step.id,
            step_token,
            self.agent_class,
            self.user_id,
            self.autonomy_level
        ):
            state.error = f"Invalid token for step {step.id}"
            return {"status": "error", "message": state.error}
        
        # Execute step
        try:
            action = {
                "step_id": step.id,
                "action": step.action_type,
                "resource": step.resource,
                "intent": step.description,
            }
            state.actions.append(action)
            
            result = self.tool_executor(step)
            state.step_results.append(result)
            state.observations.append(f"Executed {step.action_type} on {step.resource}: {result.get('result', 'OK')}")
            state.current_step_index += 1
            
            if state.current_step_index >= len(state.plan.steps):
                state.finished = True
            
            return {"status": "success", "result": result}
        except Exception as e:
            state.error = f"Step execution failed: {str(e)}"
            return {"status": "error", "message": state.error}
    
    def run(self, intent: str, max_iterations: int = 10) -> ReActState:
        """Run the ReAct loop."""
        state = self.initialize(intent)
        
        if state.error:
            return state
        
        # Check consent
        if not self.check_consent(state):
            state.error = "Plan not approved"
            return state
        state.consent_given = True
        
        # ReAct loop
        for _ in range(max_iterations):
            if state.finished or state.error:
                break
            
            # Reason
            thought = self.reason(state)
            
            # Act
            action_result = self.act(state)
            
            if action_result["status"] == "error":
                break
            elif action_result["status"] == "complete":
                break
        
        return state
    
    def get_summary(self, state: ReActState) -> Dict[str, Any]:
        """Get a summary of the ReAct execution."""
        return {
            "plan_id": state.plan.id if state.plan else None,
            "intent": state.plan.description if state.plan else None,
            "steps_planned": len(state.plan.steps) if state.plan else 0,
            "steps_executed": len(state.step_results),
            "thoughts": state.thoughts,
            "actions": state.actions,
            "observations": state.observations,
            "consent_given": state.consent_given,
            "finished": state.finished,
            "error": state.error,
        }


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    adapter = ReActAdapter(
        agent_class="coding",
        user_id="user123",
        autonomy_level=2
    )
    
    intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    result = adapter.run(intent)
    
    summary = adapter.get_summary(result)
    print(f"Plan: {summary['plan_id']}")
    print(f"Intent: {summary['intent']}")
    print(f"Steps planned: {summary['steps_planned']}")
    print(f"Steps executed: {summary['steps_executed']}")
    print(f"Consent given: {summary['consent_given']}")
    print(f"Finished: {summary['finished']}")
    print(f"Error: {summary['error']}")
    print("\nThoughts:")
    for t in summary['thoughts']:
        print(f"  - {t}")
    print("\nActions:")
    for a in summary['actions']:
        print(f"  - {a}")
    print("\nObservations:")
    for o in summary['observations']:
        print(f"  - {o}")