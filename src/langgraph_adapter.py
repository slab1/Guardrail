"""Adapter for LangGraph integration with Guardrail."""
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from plan_compiler.enhanced_plan_compiler import ValidatedPlan, ValidatedStep, compile_and_validate_plan
from token_service import validate_step_token_for_execution
from consent_manager import is_plan_approved, is_step_approved


@dataclass
class GuardrailState:
    """State for Guardrail-enabled LangGraph."""
    plan: Optional[ValidatedPlan] = None
    current_step_index: int = 0
    step_results: List[Dict[str, Any]] = None
    consent_given: bool = False
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.step_results is None:
            self.step_results = []


class LangGraphAdapter:
    """Adapter to integrate Guardrail with LangGraph workflows."""
    
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
    
    def create_plan_node(self, intent: str) -> Callable[[GuardrailState], GuardrailState]:
        """Create a LangGraph node that compiles and validates a plan."""
        def node(state: GuardrailState) -> GuardrailState:
            vplan = compile_and_validate_plan(
                intent=intent,
                agent_class=self.agent_class,
                user_id=self.user_id,
                autonomy_level=self.autonomy_level,
            )
            state.plan = vplan
            state.current_step_index = 0
            state.step_results = []
            state.error = None
            if vplan.validation_errors:
                state.error = f"Plan validation failed: {vplan.validation_errors}"
            return state
        return node
    
    def consent_node(self) -> Callable[[GuardrailState], GuardrailState]:
        """Create a LangGraph node that handles consent."""
        def node(state: GuardrailState) -> GuardrailState:
            if not state.plan:
                state.error = "No plan available for consent"
                return state
            
            if state.plan.consent_given:
                return state
            
            # Check if already approved via consent manager
            if is_plan_approved(state.plan.id):
                state.plan.consent_given = True
                state.consent_given = True
                return state
            
            # In a real implementation, this would trigger UI consent flow
            # For now, auto-approve for testing
            state.plan.consent_given = True
            state.consent_given = True
            return state
        return node
    
    def execute_step_node(self) -> Callable[[GuardrailState], GuardrailState]:
        """Create a LangGraph node that executes the current step."""
        def node(state: GuardrailState) -> GuardrailState:
            if not state.plan or state.error:
                return state
            
            if state.current_step_index >= len(state.plan.steps):
                return state
            
            step = state.plan.steps[state.current_step_index]
            
            # Check step consent
            if not is_step_approved(state.plan.id, step.id):
                state.error = f"Step {step.id} not approved"
                return state
            
            # Validate step token
            step_token = state.plan.step_tokens.get(step.id)
            if not step_token:
                state.error = f"No token for step {step.id}"
                return state
            
            if not validate_step_token_for_execution(
                state.plan.id,
                step.id,
                step_token,
                self.agent_class,
                self.user_id,
                self.autonomy_level
            ):
                state.error = f"Invalid token for step {step.id}"
                return state
            
            # Execute the step
            try:
                result = self.tool_executor(step)
                state.step_results.append(result)
                state.current_step_index += 1
            except Exception as e:
                state.error = f"Step execution failed: {str(e)}"
            
            return state
        return node
    
    def should_continue(self, state: GuardrailState) -> str:
        """Conditional edge function to decide whether to continue executing steps."""
        if state.error:
            return "error"
        if not state.plan:
            return "error"
        if state.current_step_index >= len(state.plan.steps):
            return "complete"
        return "continue"
    
    def build_workflow(self, intent: str):
        """Build a complete LangGraph workflow."""
        try:
            from langgraph.graph import StateGraph, END
        except ImportError:
            raise ImportError("langgraph is required. Install with: pip install langgraph")
        
        workflow = StateGraph(GuardrailState)
        
        # Add nodes
        workflow.add_node("create_plan", self.create_plan_node(intent))
        workflow.add_node("consent", self.consent_node())
        workflow.add_node("execute_step", self.execute_step_node())
        
        # Add edges
        workflow.set_entry_point("create_plan")
        workflow.add_edge("create_plan", "consent")
        workflow.add_edge("consent", "execute_step")
        workflow.add_conditional_edges(
            "execute_step",
            self.should_continue,
            {
                "continue": "execute_step",
                "complete": END,
                "error": END,
            }
        )
        
        return workflow.compile()
    
    def run(self, intent: str) -> GuardrailState:
        """Run the complete workflow."""
        workflow = self.build_workflow(intent)
        initial_state = GuardrailState()
        return workflow.invoke(initial_state)


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # This will only work if langgraph is installed
    try:
        adapter = LangGraphAdapter(
            agent_class="coding",
            user_id="user123",
            autonomy_level=2
        )
        
        intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
        result = adapter.run(intent)
        
        print(f"Plan: {result.plan.id if result.plan else 'None'}")
        print(f"Consent given: {result.consent_given}")
        print(f"Steps executed: {len(result.step_results)}")
        print(f"Error: {result.error}")
        for r in result.step_results:
            print(f"  - {r}")
    except ImportError as e:
        print(f"LangGraph not available: {e}")