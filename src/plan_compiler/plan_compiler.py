"""Plan compiler module for Guardrail.

Provides a function to convert a natural language intent into a structured plan.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import hashlib
from datetime import datetime

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
    
    if "resource" in step_dict and step_dict["resource"] and not re.match(r'^[a-zA-Z0-9/_\-.\/ ]+$', step_dict["resource"]):
        return False
    
    return True

def _build_plan_from_intent(intent: str, plan_id: str) -> Plan:
    """
    Convert a raw intent string into a structured Plan object.
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
        action_type = verb_to_action.get(verb, verb)
        
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
    
    # Dummy model requirement
    model_required = "nvidia/nemotron-3-nano-30b-a3b-reasoning"
    
    plan = Plan(
        id=plan_id,
        description=description,
        steps=steps,
        model_required=model_required,
        created_at=datetime.utcnow().isoformat() + "Z"
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
# Enhanced Plan Compiler (new API)
# ----------------------------------------------------------------------
class ActionType:
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    VERIFY = "verify"
    MONITOR = "monitor"
    UNKNOWN = "unknown"

class ValidatedPlanEnhanced:
    def __init__(self, id, description, steps, plan_token, step_tokens, validation_errors, created_at, policy_compliance=True, compliance_report=None):
        self.id = id
        self.description = description
        self.steps = steps
        self.plan_token = plan_token
        self.step_tokens = step_tokens
        self.validation_errors = validation_errors
        self.created_at = created_at
        self.policy_compliance = policy_compliance
        self.compliance_report = compliance_report

@dataclass
class ValidatedStepEnhanced:
    id: str
    action_type: str
    resource: str
    reversible: bool
    step_token: str
    policy_compliance: bool = True
    compliance_issue: Optional[str] = None
    required_policy: Optional[str] = None

class PlanCompiler:
    def __init__(self, verifier):
        self.verifier = verifier
        self.known_actions = {
            'read': "read",
            'write': "write",
            'execute': "execute",
            'admin': "admin",
            'verify': "verify",
            'monitor': "monitor",
            'read file': "read",
            'write file': "write",
            'execute command': "execute",
            'admin task': "admin",
            'verify system': "verify",
            'monitor network': "monitor"
        }
    
    def compile_and_validate_plan(self, intent: str, agent_class: str, user_id: str, autonomy_level: int) -> ValidatedPlanEnhanced:
        print(f"Processing intent: {intent}")
        
        steps_data = self._parse_intent_enhanced(intent)
        steps = self._create_steps_enhanced(steps_data, autonomy_level)
        compliance_result = self._validate_plan_compliance_enhanced(steps, autonomy_level)
        
        plan_id = f"verify_{abs(hash(intent)) % 100000000:08x}"
        plan_description = self._generate_plan_description(intent)
        
        return ValidatedPlanEnhanced(
            id=plan_id,
            description=plan_description,
            steps=steps,
            plan_token=True,
            step_tokens=self._generate_step_tokens_enhanced(steps),
            validation_errors=self._get_validation_errors_enhanced(compliance_result),
            created_at=datetime.utcnow().isoformat() + "Z",
            policy_compliance=compliance_result['valid'],
            compliance_report=compliance_result['report']
        )
    
    def _parse_intent_enhanced(self, intent: str) -> List[Dict[str, Any]]:
        intent = intent.lower().strip()
        actions = []
        
        if re.search(r'file.*read', intent):
            actions.append({'action': 'read file', 'action_type': 'read', 'resource': 'config.yaml', 'priority': 1})
        if re.search(r'file.*write', intent):
            actions.append({'action': 'write file', 'action_type': 'write', 'resource': 'config.yaml', 'priority': 1})
        if re.search(r'system.*modify', intent):
            actions.append({'action': 'system_modify', 'action_type': 'execute', 'resource': 'system', 'priority': 2})
        if re.search(r'system.*monitor', intent):
            actions.append({'action': 'monitor', 'action_type': 'monitor', 'resource': 'network', 'priority': 2})
        if re.search(r'verify', intent):
            actions.append({'action': 'verify', 'action_type': 'verify', 'resource': 'system', 'priority': 3})
        
        if not actions:
            actions.append({'action': 'read file', 'action_type': 'read', 'resource': 'config.yaml', 'priority': 1})
        
        actions.sort(key=lambda x: x['priority'])
        return actions
    
    def _create_steps_enhanced(self, actions: List[Dict[str, Any]], autonomy_level: int) -> List[ValidatedStepEnhanced]:
        steps = []
        for action in actions:
            step = ValidatedStepEnhanced(
                id=f"step_{len(steps) + 1:03d}",
                action_type=action['action_type'],
                resource=action['resource'],
                reversible=False,
                step_token=f"token_{len(steps) + 1:03d}"
            )
            compliance_result = self._check_step_compliance_enhanced(step, autonomy_level)
            step.policy_compliance = compliance_result['valid']
            if not compliance_result['valid']:
                step.compliance_issue = compliance_result['issue']
                step.required_policy = compliance_result['required_policy']
            steps.append(step)
        return steps
    
    def _validate_plan_compliance_enhanced(self, steps: List[ValidatedStepEnhanced], autonomy_level: int) -> Dict[str, Any]:
        all_valid = True
        compliance_issues = []
        
        for step in steps:
            if not step.policy_compliance:
                compliance_issues.append(f"Step {step.id} violates {step.compliance_issue}")
                all_valid = False
        
        return {
            'valid': all_valid,
            'report': '\n'.join(compliance_issues) if compliance_issues else "Plan is fully compliant with policies"
        }
    
    def _check_step_compliance_enhanced(self, step: ValidatedStepEnhanced, autonomy_level: int) -> Dict[str, Any]:
        result = {'valid': True, 'issue': None, 'required_policy': None}
        
        if step.action_type == "write" and step.resource in ['config.yaml', 'system', 'network']:
            if autonomy_level < 1:
                result['valid'] = False
                result['issue'] = "Write operations require minimum autonomy level 1"
                result['required_policy'] = "safety_002"
        
        if step.action_type == "read" and step.resource == 'config.yaml':
            if autonomy_level < 0:
                result['valid'] = False
                result['issue'] = "Read operations require valid autonomy level"
                result['required_policy'] = "safety_003"
        
        if step.action_type == "admin":
            if autonomy_level < 3:
                result['valid'] = False
                result['issue'] = "Admin actions require maximum autonomy level 3"
                result['required_policy'] = "safety_001"
        
        if step.action_type == "verify":
            if autonomy_level < 2:
                result['valid'] = False
                result['issue'] = "Verification requires minimum autonomy level 2"
                result['required_policy'] = "safety_003"
        
        return result
    
    def _generate_plan_description(self, intent: str) -> str:
        return f"Automated plan for: {intent}"
    
    def _generate_step_tokens_enhanced(self, steps: List[ValidatedStepEnhanced]) -> Dict[str, str]:
        tokens = {}
        for step in steps:
            tokens[step.id] = step.step_token
        return tokens
    
    def _get_validation_errors_enhanced(self, compliance_result: Dict[str, Any]) -> List[str]:
        errors = []
        if not compliance_result['valid']:
            errors.append("Plan has validation issues")
            if compliance_result['report']:
                for line in compliance_result['report'].split('\n'):
                    errors.append(f"Validation error: {line}")
        else:
            errors.append("Plan is valid and policy compliant")
        return errors

# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    example_intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    plan = compile_plan(example_intent, plan_id="demo_intent_001")
    print_plan_summary(plan)
    assert validate_plan(plan), "Plan validation failed"
