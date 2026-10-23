"""Tests for the MCP gateway."""
import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_gateway import (
    MCPRequest,
    MCPResponse,
    create_gateway,
    create_client,
    is_action_allowed,
    is_tool_allowed,
    category_of_tool,
    required_level_for_category,
    AutonomyLevel,
)


def test_gateway_allows_read_for_l0():
    """Test that L0 autonomy can perform read actions."""
    gateway = create_gateway()
    request = MCPRequest(
        tool_name="file_read",
        args={"path": "/etc/config.yaml"},
        intent="Read config",
        user_id="user1",
        autonomy_level=AutonomyLevel.L0,
        agent_class="coding"
    )
    response = gateway.handle_request(request)
    assert response.success is True
    assert response.result is not None


def test_gateway_blocks_write_for_l0():
    """Test that L0 autonomy cannot perform write actions."""
    gateway = create_gateway()
    request = MCPRequest(
        tool_name="file_write",
        args={"path": "/etc/config.yaml", "content": "test"},
        intent="Write config",
        user_id="user1",
        autonomy_level=AutonomyLevel.L0,
        agent_class="coding"
    )
    response = gateway.handle_request(request)
    assert response.success is False
    assert "not allowed" in response.error


def test_gateway_allows_write_for_l1():
    """Test that L1 autonomy can perform write actions."""
    gateway = create_gateway()
    request = MCPRequest(
        tool_name="file_write",
        args={"path": "/etc/config.yaml", "content": "test"},
        intent="Write config",
        user_id="user1",
        autonomy_level=AutonomyLevel.L1,
        agent_class="coding"
    )
    response = gateway.handle_request(request)
    assert response.success is True


def test_gateway_blocks_execute_for_l1():
    """Test that L1 autonomy cannot perform execute actions."""
    gateway = create_gateway()
    request = MCPRequest(
        tool_name="shell_command",
        args={"command": "ls"},
        intent="List directory",
        user_id="user1",
        autonomy_level=AutonomyLevel.L1,
        agent_class="coding"
    )
    response = gateway.handle_request(request)
    assert response.success is False


def test_gateway_allows_execute_for_l2():
    """Test that L2 autonomy can perform execute actions."""
    gateway = create_gateway()
    request = MCPRequest(
        tool_name="shell_command",
        args={"command": "ls"},
        intent="List directory",
        user_id="user1",
        autonomy_level=AutonomyLevel.L2,
        agent_class="coding"
    )
    response = gateway.handle_request(request)
    assert response.success is True


def test_agent_policy_enforcement():
    """Test that agent class policies are enforced."""
    # file_organizer agent should not have shell_command
    assert is_tool_allowed("shell_command", "coding") is True
    assert is_tool_allowed("shell_command", "file_organizer") is False


def test_category_mapping():
    """Test tool category mapping."""
    assert category_of_tool("file_read") == "read"
    assert category_of_tool("file_write") == "write"
    assert category_of_tool("shell_command") == "execute"
    assert category_of_tool("admin_tool") == "admin"
    assert category_of_tool("unknown_tool") == "unknown"


def test_required_levels():
    """Test required autonomy levels for categories."""
    assert required_level_for_category("read") == 0
    assert required_level_for_category("write") == 1
    assert required_level_for_category("execute") == 2
    assert required_level_for_category("admin") == 3
    assert required_level_for_category("unknown") == 3  # default


def test_client_integration():
    """Test the client integration."""
    client = create_client()
    response = client.file_read(
        path="/etc/config.yaml",
        intent="Read config",
        user_id="user1",
        autonomy_level=AutonomyLevel.L1,
        agent_class="coding"
    )
    assert response.success is True


if __name__ == "__main__":
    # Run tests manually
    test_gateway_allows_read_for_l0()
    test_gateway_blocks_write_for_l0()
    test_gateway_allows_write_for_l1()
    test_gateway_blocks_execute_for_l1()
    test_gateway_allows_execute_for_l2()
    test_agent_policy_enforcement()
    test_category_mapping()
    test_required_levels()
    test_client_integration()
    print("All tests passed!")