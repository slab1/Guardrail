import uuid
from typing import List, Dict, Any, Optional

class PlanStep:
    def __init__(self, id: str, description: str, action_type: str, resource: str):
        self.id = id
        self.description = description
        self.action_type = action_type
        self.resource = resource

class AgentPlan:
    def __init__(self, intent: str, agent_class: str, user_id: str):
        self.id = f"plan_{uuid.uuid4().hex[:8]}"
        self.intent = intent
        self.description = f"Generated Plan for intent: {intent}"
        self.agent_class = agent_class
        self.user_id = user_id
        self.steps: List[PlanStep] = []
        self.validation_errors: List[str] = []
        self.consent_required: bool = False

class AgentResult:
    def __init__(self, success: bool, message: str, data: Any = None):
        self.success = success
        self.message = message
        self.data = data

class GuardrailAgent:
    def __init__(
        self,
        agent_class: str = "coding",
        user_id: str = "default_user",
        autonomy_level: int = 1,
        enable_audit: bool = True,
        enable_autopilot: bool = True
    ):
        self.agent_class = agent_class
        self.user_id = user_id
        self.autonomy_level = autonomy_level
        self.enable_audit = enable_audit
        self.enable_autopilot = enable_autopilot

    def create_plan(self, intent: str) -> AgentPlan:
        plan = AgentPlan(intent, self.agent_class, self.user_id)
        
        # Simple intent parsing simulation
        if "read" in intent.lower():
            plan.steps.append(PlanStep("step_1", "Read file", "file_read", "/workspace/README.md"))
        if "write" in intent.lower() or "create" in intent.lower():
            plan.steps.append(PlanStep("step_2", "Write file", "file_write", "/workspace/output.txt"))
            plan.consent_required = True
        if "run" in intent.lower() or "execute" in intent.lower():
            plan.steps.append(PlanStep("step_3", "Execute command", "shell_command", "npm test"))
            plan.consent_required = True
            
        if not plan.steps:
            plan.steps.append(PlanStep("step_1", "Generic Inspection", "file_read", "/workspace/"))
            
        return plan
