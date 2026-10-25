"""Policy enforcement and templates for the MCP gateway."""
from typing import Dict, Set, Any, Optional
from .types import MCPRequest, MCPResponse  # Import types


# ----------------------------------------------------------------------
# Autonomy levels (L0-L3)
# ----------------------------------------------------------------------
class AutonomyLevel:
    L0 = 0  # Minimal autonomy: only read-only actions
    L1 = 1  # Limited autonomy: read/write, basic execute
    L2 = 2  # Moderate autonomy: read/write/execute, no admin
    L3 = 3  # Full autonomy: all actions, including admin

    @classmethod
    def from_int(cls, level: int) -> int:
        if level == 0:
            return cls.L0
        elif level == 1:
            return cls.L1
        elif level == 2:
            return cls.L2
        elif level == 3:
            return cls.L3
        else:
            raise ValueError(f"Invalid autonomy level: {level}")


# ----------------------------------------------------------------------
# Category mapping (tool_name -> category)
# ----------------------------------------------------------------------
TOOL_CATEGORY: Dict[str, str] = {
    "file_read": "read",
    "file_write": "write",
    "file_delete": "write",
    "file_list": "read",
    "http_get": "read",
    "http_post": "write",
    "http_put": "write",
    "http_delete": "write",
    "shell_command": "execute",
    "shell_exec": "execute",
    "admin_tool": "admin",
}


# ----------------------------------------------------------------------
# Category to required autonomy level mapping
# ----------------------------------------------------------------------
CATEGORY_REQUIRED_LEVEL = {
    "read": 0,      # L0 sufficient
    "write": 1,     # L1 sufficient
    "execute": 2,   # L2 sufficient
    "admin": 3,     # L3 sufficient
}


def _category_of_tool(tool_name: str) -> str:
    """Map a tool_name to its category."""
    return TOOL_CATEGORY.get(tool_name, "unknown")


def _required_level_for_category(category: str) -> int:
    """Return the minimum autonomy level required for a category."""
    return CATEGORY_REQUIRED_LEVEL.get(category, 3)  # default to admin (L3)


# ----------------------------------------------------------------------
# Agent-specific policy templates
# ----------------------------------------------------------------------
# Each agent class defines which tool_names it is allowed to invoke.
AGENT_POLICIES: Dict[str, Set[str]] = {
    "coding": {
        "file_read", "file_write", "file_delete", "file_list",
        "http_get", "http_post", "http_put", "http_delete",
        "shell_command", "shell_exec",
        "database_query", "database_update",
    },
    "data_analysis": {
        "file_read", "file_write", "file_delete", "file_list",
        "http_get", "http_post", "http_put", "http_delete",
        "shell_command", "shell_exec",
        "database_query", "database_update",
    },
    "travel_booking": {
        "http_get", "http_post", "http_put", "http_delete",
        "shell_command", "shell_exec",
        "file_read", "file_write",
    },
    "email_comms": {
        "http_get", "http_post", "http_put", "http_delete",
        "shell_command", "shell_exec",
        "file_read", "file_write",
    },
    "file_organizer": {
        "file_read", "file_write", "file_delete", "file_list",
        "http_get", "http_post",
    },
}


def is_tool_allowed(tool_name: str, agent_class: str) -> bool:
    """Check if the given tool_name is allowed for the given agent_class."""
    return tool_name in AGENT_POLICIES.get(agent_class, set())


def category_of_tool(tool_name: str) -> str:
    """Map a tool_name to its category."""
    return TOOL_CATEGORY.get(tool_name, "unknown")


def required_level_for_category(category: str) -> int:
    """Return the minimum autonomy level required for a category."""
    return CATEGORY_REQUIRED_LEVEL.get(category, 3)  # default to admin (L3)


def is_action_allowed(request: MCPRequest) -> bool:
    """
    Determine if the request is allowed based on:
    1. Agent policy (allowed tool_names for the agent class)
    2. Autonomy level (category required level)
    """
    # 1. Agent policy check
    if not is_tool_allowed(request.tool_name, request.agent_class):
        return False

    # 2. Category check
    category = _category_of_tool(request.tool_name)
    if category == "unknown":
        return False

    required_level = _required_level_for_category(category)
    return request.autonomy_level >= required_level


def print_policy_debug(request: MCPRequest):
    """Debug helper to print policy evaluation details."""
    cat = _category_of_tool(request.tool_name)
    req_level = request.autonomy_level
    allowed_by_agent = is_tool_allowed(request.tool_name, request.agent_class)
    cat_level = required_level_for_category(cat)
    allowed_by_autonomy = req_level >= required_level_for_category(cat)
    print(f"Tool: {request.tool_name} -> Category: {cat} (req_level={required_level_for_category(cat)})")
    print(f"Agent {request.agent_class} allows tool: {allowed_by_agent}")
    print(f"Autonomy level {req_level} >= required {required_level_for_category(cat)}? {req_level >= required_level_for_category(cat)}")
    print(f"Allowed by agent policy: {allowed_by_agent}")
    print(f"Allowed by autonomy: {allowed_by_autonomy}")
    print(f"Overall allowed: {allowed_by_agent and allowed_by_autonomy}")