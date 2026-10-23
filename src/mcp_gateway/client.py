"""MCP Gateway client for sending requests to the gateway."""
from typing import Any, Dict, Optional
from .types import MCPRequest, MCPResponse
from .server import MCPGateway, create_gateway


class MCPClient:
    """Client for interacting with the MCP gateway."""

    def __init__(self, gateway: Optional[MCPGateway] = None):
        self.gateway = gateway or create_gateway()

    def call_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        intent: str,
        user_id: str,
        autonomy_level: int,
        agent_class: str
    ) -> MCPResponse:
        """Send a tool call request to the gateway."""
        request = MCPRequest(
            tool_name=tool_name,
            args=args,
            intent=intent,
            user_id=user_id,
            autonomy_level=autonomy_level,
            agent_class=agent_class
        )
        return self.gateway.handle_request(request)

    def file_read(self, path: str, intent: str, user_id: str, autonomy_level: int, agent_class: str) -> MCPResponse:
        """Read a file."""
        return self.call_tool(
            tool_name="file_read",
            args={"path": path},
            intent=intent,
            user_id=user_id,
            autonomy_level=autonomy_level,
            agent_class=agent_class
        )

    def file_write(self, path: str, content: str, intent: str, user_id: str, autonomy_level: int, agent_class: str) -> MCPResponse:
        """Write a file."""
        return self.call_tool(
            tool_name="file_write",
            args={"path": path, "content": content},
            intent=intent,
            user_id=user_id,
            autonomy_level=autonomy_level,
            agent_class=agent_class
        )

    def http_get(self, url: str, intent: str, user_id: str, autonomy_level: int, agent_class: str) -> MCPResponse:
        """Make an HTTP GET request."""
        return self.call_tool(
            tool_name="http_get",
            args={"url": url},
            intent=intent,
            user_id=user_id,
            autonomy_level=autonomy_level,
            agent_class=agent_class
        )

    def shell_command(self, command: str, intent: str, user_id: str, autonomy_level: int, agent_class: str) -> MCPResponse:
        """Execute a shell command."""
        return self.call_tool(
            tool_name="shell_command",
            args={"command": command},
            intent=intent,
            user_id=user_id,
            autonomy_level=autonomy_level,
            agent_class=agent_class
        )


def create_client(gateway: Optional[MCPGateway] = None) -> MCPClient:
    """Factory function to create an MCP client."""
    return MCPClient(gateway)