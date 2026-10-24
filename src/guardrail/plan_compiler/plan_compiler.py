"""Plan compiler module for Guardrail.

Provides a function to convert a natural language intent into a structured plan.
"""
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# ----------------------------------------------------------------------
# Data structures
# ----------------------------------------------------------------------
@dataclass
class Step:
    """A single step in the plan."""
    id: str
    description: str
    action_type: str  # e.g., "file_read", "http_request", "shell_command"
    resource: Optional[str] = None  # e.g., file path, URL
    pre_conditions: Optional[List[str]] = None
    post_conditions: Optional[List[str]] = None

@dataclass
class Plan:
    """Container for a validated plan."""
    id: str
    description: str
    steps: List[Step]
    model_required: str  # e.g., "nvidia/nemotron-3-nano-30b-a3b-reasoning"
    created_at: str  # ISO timestamp

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def _parse_intent(intent: str) -> Dict[str, Any]:
    """
    Very naive parser that extracts:
      - a short description
      - a list of actions (verbs + objects)
    Returns a dict with 'description' and 'actions' list.
    """
    # Normalize whitespace
    intent = " ".join(intent.strip().split())
    
    # Simple heuristic: split on verbs that are followed by nouns
    # This is a very naive approach; in production we'd use a proper parser.
    # Capture the verb and the object
    verbs = re.findall(r'\b(create|read|write|delete|list|download|upload|modify|execute|run|query|fetch|submit|review|approve|deny)\b\s+([^,\.\n]+)', intent, flags=re.IGNORECASE)
    
    actions = []
    for verb, obj in verbs:
        actions.append({
            "verb": verb.lower(),
            "object": obj.strip()
        })
    
    # Build a simple description
    description = " ".join([verb + " " + obj for verb, obj in verbs]) if verbs else "No explicit actions detected"
    
    return {
        "description": description,
        "actions": actions
    }

def _generate_step_id(prefix: str, idx: int) -> str:
    """Generate a unique step identifier."""
    return f"{prefix}_{idx:03d}"

def _validate_step(step_dict: Dict[str, Any]) -> bool:
    """
    Very lightweight validation:
    - action_type must be in a whitelist
    - resource must match a simple pattern if provided
    """
    allowed_actions = {
        "file_read", "file_write", "file_delete", "file_list",
        "http_get", "http_post", "http_put", "http_delete",
        "shell_command", "shell_pipe", "shell_exec",
        "openapi_call", "database_query", "database_update"
    }
    
    if step_dict["action_type"] not in allowed_actions:
        return False
    
    if "resource" in step_dict and not re.match(r'^[a-zA-Z0-9/_\-\.\/]+$', step_dict["resource"]):
        return False
    
    return True

def _build_plan_from_intent(intent: str, plan_id: str) -> Plan:
    """
    Convert a raw intent string into a structured Plan object.
    This is a placeholder implementation; in production it would use a
    more sophisticated parser (e.g., LLM-based plan generation).
    """
    parsed = _parse_intent(intent)
    description = parsed["description"]
    actions = parsed["actions"]
    
    # Map natural language verbs to valid action types
    verb_to_action = {
        "create": "file_write",
        "read": "file_read",
        "write": "file_write",
        "delete": "file_delete",
        "list": "file_list",
        "download": "http_get",
        "upload": "http_post",
        "modify": "file_write",
        "execute": "shell_command",
        "run": "shell_command",
        "query": "database_query",
        "fetch": "http_get",
        "submit": "http_post",
        "review": "file_read",
        "approve": "file_read",
        "deny": "file_read",
    }
    
    steps: List[Step] = []
    for idx, act in enumerate(actions, start=1):
        step_id = _generate_step_id("step", idx)
        verb = act["verb"]
        obj = act["object"]
        action_type = verb_to_action.get(verb, verb)  # fallback to verb if not mapped
        
        # Better resource detection
        resource = None
        if action_type.startswith("file_") or action_type.startswith("shell_"):
            resource = obj
        elif action_type.startswith("http_"):
            resource = obj
        elif action_type.startswith("database_"):
            resource = obj
        
        step = Step(
            id=step_id,
            description=f"Step {idx}: {verb.title()} {obj}",
            action_type=action_type,
            resource=resource,
            pre_conditions=[],
            post_conditions=[]
        )
        steps.append(step)
    
    # Dummy model requirement – in real system this would be resolved
    model_required = "nvidia/nemotron-3-nano-30b-a3b-reasoning"
    
    plan = Plan(
        id=plan_id,
        description=description,
        steps=steps,
        model_required=model_required,
        created_at="2026-01-01T00:00:00Z"  # placeholder; real system would use datetime.now()
    )
    return plan

def compile_plan(intent: str, plan_id: Optional[str] = None) -> Plan:
    """
    Public API: compile a plan from a natural language intent.
    
    Args:
        intent: Natural language description of what the user wants the agent to do.
        plan_id: Optional identifier for the plan; if None, a deterministic ID is generated.
    
    Returns:
        Plan object containing the structured steps.
    """
    if plan_id is None:
        import hashlib
        plan_id = hashlib.sha256(intent.encode('utf-8')).hexdigest()[:8]
    
    plan = _build_plan_from_intent(intent, plan_id=plan_id)
    return plan

def validate_plan(plan: Plan) -> bool:
    """
    Validate the plan structure.
    Currently only checks that all steps have a valid action_type.
    Returns True if valid, False otherwise.
    """
    if not plan.steps:
        return False
    
    for step in plan.steps:
        if not _validate_step(step.__dict__):
            return False
    return True

def print_plan_summary(plan: Plan) -> None:
    """Pretty-print a short summary of the plan."""
    print(f"Plan ID: {plan.id}")
    print(f"Description: {plan.description}")
    print(f"Model required: {plan.model_required}")
    print(f"Created at: {plan.created_at}")
    print("\nSteps:")
    for step in plan.steps:
        print(f"  [{step.id}] {step.description}")
        if step.resource:
            print(f"    Resource: {step.resource}")
        if step.pre_conditions:
            print(f"    Preconditions: {', '.join(step.pre_conditions)}")
        if step.post_conditions:
            print(f"    Postconditions: {', '.join(step.post_conditions)}")
    print()

# ----------------------------------------------------------------------
# Example usage (will only run when module is executed directly)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Example intent
    example_intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    plan = compile_plan(example_intent, plan_id="demo_intent_001")
    print_plan_summary(plan)
    assert validate_plan(plan), "Plan validation failed"


class PlanCompiler:
    """Plan compiler class for programmatic use."""
    
    def __init__(self, default_model: str = "nvidia/nemotron-3-nano-30b-a3b-reasoning"):
        self.default_model = default_model
    
    def compile(self, intent: str, plan_id: Optional[str] = None) -> Plan:
        """Compile a plan from intent."""
        return compile_plan(intent, plan_id)
    
    def validate(self, plan: Plan) -> bool:
        """Validate a plan."""
        return validate_plan(plan)