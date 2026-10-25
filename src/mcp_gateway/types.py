"""MCP Gateway types and utilities."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class MCPRequest:
    """Request sent to the MCP gateway."""
    tool_name: str
    args: Dict[str, Any]
    intent: str
    user_id: str
    autonomy_level: int  # 0=L0, 1=L1, 3=L3 (autonomy levels)
    agent_class: str  # e.g., "coding", "data_analysis", etc.


@dataclass
class MCPResponse:
    """Response returned from the MCP gateway."""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None