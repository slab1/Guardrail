"""Tests for NVIDIA adapter."""
import sys
import os

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from nvidia_adapter import NvidiaAdapter, NvidiaAgentState


def test_nvidia_adapter_creation():
    """Test NvidiaAdapter can be created."""
    adapter = NvidiaAdapter()
    assert adapter is not None
    assert adapter.model_name == "nvidia/nemotron-3-ultra-550b-a55b"


def test_nvidia_adapter_custom_model():
    """Test NvidiaAdapter with custom model."""
    adapter = NvidiaAdapter(model_name="nvidia/nemotron-3-nano-30b-a3b-reasoning")
    assert adapter.model_name == "nvidia/nemotron-3-nano-30b-a3b-reasoning"


def test_nvidia_adapter_create_plan():
    """Test plan creation."""
    adapter = NvidiaAdapter(agent_class="coding", user_id="user1", autonomy_level=1)
    plan = adapter.create_plan("Create a file and read it")
    assert plan is not None
    assert len(plan.steps) > 0


def test_nvidia_adapter_function_calling_tools():
    """Test function calling tools generation."""
    adapter = NvidiaAdapter()
    tools = adapter.create_nvidia_function_calling_tools()
    assert len(tools) == 3
    tool_names = [t["name"] for t in tools]
    assert "guardrail_execute_plan" in tool_names
    assert "guardrail_check_consent" in tool_names
    assert "guardrail_validate_token" in tool_names


def test_nvidia_adapter_model_config():
    """Test model config generation."""
    adapter = NvidiaAdapter()
    config = adapter.get_model_config()
    assert config["model"] == "nvidia/nemotron-3-ultra-550b-a55b"
    assert "functions" in config
    assert config["function_call"] == "auto"


def test_nvidia_adapter_run_agent():
    """Test full agent run (without consent - will fail consent check)."""
    adapter = NvidiaAdapter(agent_class="coding", user_id="user1", autonomy_level=1)
    result = adapter.run_agent("Create a file")
    # Should fail because no consent
    assert result.error == "Plan not approved"
    assert not result.consent_given


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])