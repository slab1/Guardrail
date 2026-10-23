"""MCP Gateway server implementation."""
from typing import Any, Dict, Optional
from .types import MCPRequest, MCPResponse
from .policy import is_action_allowed, print_policy_debug


class MCPGateway:
    """MCP Gateway that enforces policies on incoming requests."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: MCPRequest) -> MCPResponse:
        """Process an MCP request and return a response."""
        self.request_count += 1

        # Debug logging
        print_policy_debug(request)

        # Policy check
        if not is_action_allowed(request):
            return MCPResponse(
                success=False,
                error=f"Action not allowed: {request.tool_name} for agent class {request.agent_class} with autonomy level {request.autonomy_level}",
                details={"tool": request.tool_name, "agent_class": request.agent_class, "autonomy_level": request.autonomy_level}
            )

        # Execute the action (mock implementation)
        result = self._execute_tool(request.tool_name, request.args)

        return MCPResponse(
            success=True,
            result=result,
            details={"tool": request.tool_name, "agent_class": request.agent_class}
        )

    def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Mock tool execution. In a real implementation, this would call the actual tool."""
        # This is a placeholder - in reality you'd integrate with actual MCP tools
        return {
            "status": "executed",
            "tool": tool_name,
            "args": args,
            "message": f"Tool {tool_name} executed successfully (mock)"
        }


def create_gateway() -> MCPGateway:
    """Factory function to create an MCP gateway instance."""
    return MCPGateway()


def main():
    """Simple CLI for testing the gateway."""
    import json
    import sys

    gateway = create_gateway()

    # Example request
    request_data = {
        "tool_name": "file_read",
        "args": {"path": "/etc/config.yaml"},
        "intent": "Read configuration file",
        "user_id": "user123",
        "autonomy_level": 1,
        "agent_class": "coding"
    }

    request = MCPRequest(**request_data)
    response = gateway.handle_request(request)

    print(f"\nResponse: {response}")
    if response.success:
        print(f"Result: {response.result}")
    else:
        print(f"Error: {response.error}")


if __name__ == "__main__":
    main()