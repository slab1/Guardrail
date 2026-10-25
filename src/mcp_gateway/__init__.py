"""MCP Gateway package."""
from .types import MCPRequest, MCPResponse
from .policy import (
    AutonomyLevel,
    is_action_allowed,
    is_tool_allowed,
    category_of_tool,
    required_level_for_category,
    print_policy_debug,
)
from .server import MCPGateway, create_gateway
from .client import MCPClient, create_client

__all__ = [
    "MCPRequest",
    "MCPResponse",
    "AutonomyLevel",
    "is_action_allowed",
    "is_tool_allowed",
    "category_of_tool",
    "required_level_for_category",
    "print_policy_debug",
    "MCPGateway",
    "create_gateway",
    "MCPClient",
    "create_client",
]