from typing import List, Dict, Any

class PolicyTemplate:
    def __init__(self, id: str, name: str, description: str, expression: str, version: str = "1.0.0"):
        self.id = id
        self.name = name
        self.description = description
        self.expression = expression
        self.version = version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "expression": self.expression,
            "version": self.version
        }

TEMPLATES = [
    PolicyTemplate(
        "read-only-workspace",
        "Read-Only Workspace",
        "Restrict agent to only reading files in the workspace directory.",
        "action == 'file_read' AND resource.startswith('/workspace/')",
        "1.0.0"
    ),
    PolicyTemplate(
        "no-egress",
        "No External Egress",
        "Prevent all outbound network connections.",
        "action != 'network_egress'",
        "1.1.0"
    ),
    PolicyTemplate(
        "supervised-write",
        "Supervised File Writes",
        "Require human consent for any file write operation.",
        "action == 'file_write' IMPLIES consent_granted == true",
        "1.0.2"
    ),
    PolicyTemplate(
        "malicious-url-filter",
        "Malicious URL Filter",
        "Block requests to known malicious domains.",
        "resource.domain NOT_IN ['evil.com', 'malware.net', 'tracking.io']",
        "2.0.0"
    ),
    PolicyTemplate(
        "temp-only-write",
        "Temp-Only Writes",
        "Restrict all file writes strictly to the /tmp/ directory.",
        "action == 'file_write' IMPLIES resource.startswith('/tmp/')",
        "1.0.0"
    ),
    PolicyTemplate(
        "no-shell-exec",
        "No Shell Execution",
        "Completely block all shell and subprocess executions.",
        "action != 'shell_command' AND action != 'subprocess_run'",
        "1.0.0"
    )
]

def list_templates() -> List[PolicyTemplate]:
    return TEMPLATES

def render_template(template_id: str, context: Dict[str, Any]) -> str:
    template = next((t for t in TEMPLATES if t.id == template_id), None)
    if not template:
        return ""
    # Simple replacement simulation
    expr = template.expression
    for key, value in context.items():
        expr = expr.replace(f"{{{{{key}}}}}", str(value))
    return expr

def generate_template_docs() -> str:
    """Generates markdown documentation for all policy templates."""
    docs = "# Guardrail Policy Template Library\n\n"
    for t in TEMPLATES:
        docs += f"## {t.name} ({t.id})\n"
        docs += f"- **Description**: {t.description}\n"
        docs += f"- **Version**: {t.version}\n"
        docs += f"- **Expression**: `{t.expression}`\n\n"
    return docs

def migrate_policy(policy_expr: str, from_version: str, to_version: str) -> str:
    """
    Simulates a policy migration/transformation between versions.
    In a real system, this would handle grammar changes or deprecated operators.
    """
    if from_version == "1.0.0" and to_version == "2.0.0":
        # Example: upgrade legacy 'action == write' to 'action.type == write'
        return policy_expr.replace("action == ", "action.type == ")
    return policy_expr
