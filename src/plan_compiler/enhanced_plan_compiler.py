"""Enhanced plan compiler with static validation and token integration."""
import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from plan_compiler.plan_compiler import compile_plan, Plan, Step
from token_service import create_plan_token, create_step_token, validate_plan_token, validate_step_token


class ActionType(Enum):
    """Enumeration of allowed action types."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_LIST = "file_list"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTP_PUT = "http_put"
    HTTP_DELETE = "http_delete"
    SHELL_COMMAND = "shell_command"
    SHELL_EXEC = "shell_exec"
    DATABASE_QUERY = "database_query"
    DATABASE_UPDATE = "database_update"


# Valid action types for validation
VALID_ACTION_TYPES: Set[str] = {a.value for a in ActionType}


# Resource glob patterns for validation
RESOURCE_PATTERNS = {
    "file": r'^[a-zA-Z0-9/_\-\.\/ ]+$',
    "url": r'^https?://[^\s]+$',
    "path": r'^[a-zA-Z0-9/_\-\.\/ ]+$',
    "command": r'^[a-zA-Z0-9_\-\/\.\s]+$',
    "sql": r'^[\w\s\*\.,\(\)\=\>\<\'\"]+$',
}


@dataclass
class ValidatedStep:
    """Step with validation metadata."""
    id: str
    description: str
    action_type: str
    resource: Optional[str] = None
    pre_conditions: List[str] = field(default_factory=list)
    post_conditions: List[str] = field(default_factory=list)
    reversible: bool = False
    reversal_action: Optional[str] = None
    resource_type: str = "unknown"
    validation_errors: List[str] = field(default_factory=list)

    @classmethod
    def from_step(cls, step: Step) -> "ValidatedStep":
        """Create a ValidatedStep from a base Step."""
        return cls(
            id=step.id,
            description=step.description,
            action_type=step.action_type,
            resource=step.resource,
            pre_conditions=step.pre_conditions or [],
            post_conditions=step.post_conditions or [],
        )


@dataclass
class ValidatedPlan:
    """Plan with validation results and tokens."""
    id: str
    description: str
    steps: List[ValidatedStep] = field(default_factory=list)
    model_required: str = ""
    created_at: str = ""
    validation_errors: List[str] = field(default_factory=list)
    plan_token: Optional[str] = None
    step_tokens: Dict[str, str] = field(default_factory=dict)
    consent_required: bool = True
    consent_given: bool = False


def _validate_step_detailed(step: ValidatedStep) -> ValidatedStep:
    """Perform detailed validation on a step."""
    # Validate action type
    if step.action_type not in VALID_ACTION_TYPES:
        step.validation_errors.append(f"Invalid action_type: {step.action_type}")
    
    # Validate resource pattern
    if step.resource:
        resource_type = _guess_resource_type(step.action_type)
        step.resource_type = resource_type
        pattern = RESOURCE_PATTERNS.get(resource_type)
        if pattern and not re.match(pattern, step.resource):
            step.validation_errors.append(f"Resource '{step.resource}' does not match pattern for {resource_type}")
    
    # Determine reversibility
    step.reversible, step.reversal_action = _check_reversibility(step.action_type, step.resource)
    
    return step


def _guess_resource_type(action_type: str) -> str:
    """Guess resource type from action type."""
    if action_type.startswith("file_"):
        return "file"
    elif action_type.startswith("http_"):
        return "url"
    elif action_type.startswith("shell_"):
        return "command"
    elif action_type.startswith("database_"):
        return "sql"
    return "unknown"


def _check_reversibility(action_type: str, resource: Optional[str]) -> tuple:
    """Check if an action is reversible and what the reversal would be."""
    reversible_map = {
        "file_write": (True, "file_delete"),
        "file_delete": (True, "file_write"),
        "http_post": (False, None),
        "http_put": (True, "http_delete"),
        "http_delete": (False, None),
        "shell_command": (False, None),
        "database_update": (True, "database_update"),
    }
    return reversible_map.get(action_type, (False, None))


def compile_and_validate_plan(
    intent: str,
    plan_id: Optional[str] = None,
    agent_class: str = "coding",
    user_id: str = "user",
    autonomy_level: int = 1
) -> ValidatedPlan:
    """
    Compile a plan from intent, validate it, and generate tokens.
    
    Args:
        intent: Natural language description of the task
        plan_id: Optional plan identifier
        agent_class: Agent class for policy enforcement
        user_id: User identifier
        autonomy_level: User's autonomy level (0-3)
    
    Returns:
        ValidatedPlan with validation results and tokens
    """
    if plan_id is None:
        plan_id = hashlib.sha256(intent.encode('utf-8')).hexdigest()[:8]
    
    # Compile base plan
    base_plan = compile_plan(intent, plan_id=plan_id)
    
    # Convert steps to ValidatedStep and validate each
    validated_steps = []
    all_errors = []
    for step in base_plan.steps:
        vstep = ValidatedStep.from_step(step)
        vstep = _validate_step_detailed(vstep)
        validated_steps.append(vstep)
        all_errors.extend(vstep.validation_errors)
    
    # Create validated plan
    vplan = ValidatedPlan(
        id=base_plan.id,
        description=base_plan.description,
        steps=validated_steps,
        model_required=base_plan.model_required,
        created_at=base_plan.created_at,
        validation_errors=all_errors,
    )
    
    # Generate plan token if no validation errors
    if not all_errors:
        vplan.plan_token = create_plan_token(
            plan_id=vplan.id,
            intent=intent,
            agent_class=agent_class,
            user_id=user_id,
            autonomy_level=autonomy_level,
        )
        
        # Generate per-step tokens
        for step in validated_steps:
            if not step.validation_errors:
                step_token = create_step_token(
                    plan_id=vplan.id,
                    step_id=step.id,
                    intent=f"Step: {step.description}",
                    agent_class=agent_class,
                    user_id=user_id,
                    autonomy_level=autonomy_level,
                )
                vplan.step_tokens[step.id] = step_token
    
    return vplan


def validate_step_token_for_execution(
    plan_id: str,
    step_id: str,
    token: str,
    agent_class: str,
    user_id: str,
    autonomy_level: int
) -> bool:
    """Validate a step token before executing an action."""
    payload = validate_step_token(token, plan_id, step_id)
    if not payload:
        return False
    # Additional checks
    if payload.agent_class != agent_class:
        return False
    if payload.user_id != user_id:
        return False
    if payload.autonomy_level != autonomy_level:
        return False
    return True


def print_validated_plan_summary(vplan: ValidatedPlan) -> None:
    """Print a detailed summary of the validated plan."""
    print(f"Plan ID: {vplan.id}")
    print(f"Description: {vplan.description}")
    print(f"Model required: {vplan.model_required}")
    print(f"Created at: {vplan.created_at}")
    print(f"Validation errors: {len(vplan.validation_errors)}")
    for err in vplan.validation_errors:
        print(f"  - {err}")
    print(f"Plan token: {'Present' if vplan.plan_token else 'None'}")
    print(f"Step tokens: {len(vplan.step_tokens)}")
    print(f"Consent required: {vplan.consent_required}")
    print(f"Consent given: {vplan.consent_given}")
    print("\nSteps:")
    for step in vplan.steps:
        print(f"  [{step.id}] {step.description}")
        print(f"    Action: {step.action_type}")
        print(f"    Resource: {step.resource} (type: {step.resource_type})")
        print(f"    Reversible: {step.reversible}" + (f" (via {step.reversal_action})" if step.reversible else ""))
        if step.validation_errors:
            print(f"    Validation errors: {step.validation_errors}")
        if step.pre_conditions:
            print(f"    Preconditions: {', '.join(step.pre_conditions)}")
        if step.post_conditions:
            print(f"    Postconditions: {', '.join(step.post_conditions)}")
        if step.id in vplan.step_tokens:
            print(f"    Step token: Present")
        else:
            print(f"    Step token: None")
    print()


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Example intent
    example_intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    vplan = compile_and_validate_plan(
        example_intent,
        plan_id="demo_intent_001",
        agent_class="coding",
        user_id="user123",
        autonomy_level=2
    )
    print_validated_plan_summary(vplan)
    
    # Test token validation
    if vplan.plan_token:
        print("Testing plan token validation...")
        payload = validate_plan_token(vplan.plan_token, vplan.id)
        print(f"  Plan token valid: {payload is not None}")
    
    for step_id, token in vplan.step_tokens.items():
        print(f"Testing step token for {step_id}...")
        valid = validate_step_token_for_execution(
            vplan.id, step_id, token, "coding", "user123", 2
        )
        print(f"  Step token valid: {valid}")