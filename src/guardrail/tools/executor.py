"""Real tool executor implementations for Guardrail adapters."""

import os
import subprocess
import json
import requests
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"


@dataclass
class ExecutionResult:
    """Result of tool execution."""
    status: ExecutionStatus
    output: Any = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: float = 0.0


class RealToolExecutor:
    """Real tool executor that actually performs operations."""
    
    def __init__(self, allowed_paths: List[str] = None, 
                 blocked_commands: List[str] = None,
                 max_file_size: int = 10 * 1024 * 1024,
                 command_timeout: int = 30):
        self.allowed_paths = allowed_paths or ["/tmp", "/var/guardrail", os.getcwd()]
        self.blocked_commands = blocked_commands or [
            "rm -rf", "mkfs", "dd", "fdisk", "shutdown", "reboot",
            "iptables", "systemctl", "service", "passwd", "useradd",
            "chmod 777", "chown root", "su ", "sudo "
        ]
        self.max_file_size = max_file_size
        self.command_timeout = command_timeout
    
    def _is_path_allowed(self, path: str) -> bool:
        """Check if path is within allowed directories."""
        abs_path = os.path.abspath(path)
        return any(abs_path.startswith(os.path.abspath(p)) for p in self.allowed_paths)
    
    def _is_command_allowed(self, command: str) -> bool:
        """Check if command is not blocked."""
        cmd_lower = command.lower().strip()
        return not any(blocked in cmd_lower for blocked in self.blocked_commands)
    
    def execute_file_read(self, path: str) -> ExecutionResult:
        """Read a file."""
        import time
        start = time.time()
        
        if not self._is_path_allowed(path):
            return ExecutionResult(
                status=ExecutionStatus.PERMISSION_DENIED,
                error=f"Path not allowed: {path}",
                duration_ms=(time.time() - start) * 1000
            )
        
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                return ExecutionResult(
                    status=ExecutionStatus.NOT_FOUND,
                    error=f"File not found: {path}",
                    duration_ms=(time.time() - start) * 1000
                )
            
            if path_obj.stat().st_size > self.max_file_size:
                return ExecutionResult(
                    status=ExecutionStatus.FAILED,
                    error=f"File too large (> {self.max_file_size} bytes)",
                    duration_ms=(time.time() - start) * 1000
                )
            
            content = path_obj.read_text(encoding='utf-8')
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                output=content,
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_file_write(self, path: str, content: str) -> ExecutionResult:
        """Write a file."""
        import time
        start = time.time()
        
        if not self._is_path_allowed(path):
            return ExecutionResult(
                status=ExecutionStatus.PERMISSION_DENIED,
                error=f"Path not allowed: {path}",
                duration_ms=(time.time() - start) * 1000
            )
        
        try:
            path_obj = Path(path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)
            path_obj.write_text(content, encoding='utf-8')
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                output=f"Written {len(content)} bytes to {path}",
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_file_delete(self, path: str) -> ExecutionResult:
        """Delete a file."""
        import time
        start = time.time()
        
        if not self._is_path_allowed(path):
            return ExecutionResult(
                status=ExecutionStatus.PERMISSION_DENIED,
                error=f"Path not allowed: {path}",
                duration_ms=(time.time() - start) * 1000
            )
        
        try:
            path_obj = Path(path)
            if path_obj.exists():
                path_obj.unlink()
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    output=f"Deleted {path}",
                    duration_ms=(time.time() - start) * 1000
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.NOT_FOUND,
                    error=f"File not found: {path}",
                    duration_ms=(time.time() - start) * 1000
                )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_shell_command(self, command: str) -> ExecutionResult:
        """Execute a shell command."""
        import time
        start = time.time()
        
        if not self._is_command_allowed(command):
            return ExecutionResult(
                status=ExecutionStatus.PERMISSION_DENIED,
                error=f"Command blocked: {command}",
                duration_ms=(time.time() - start) * 1000
            )
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                cwd=os.getcwd()
            )
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS if result.returncode == 0 else ExecutionStatus.FAILED,
                output={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                },
                exit_code=result.returncode,
                duration_ms=(time.time() - start) * 1000
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                error=f"Command timed out after {self.command_timeout}s",
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_http_get(self, url: str, headers: Dict[str, str] = None, 
                         timeout: int = 30) -> ExecutionResult:
        """Execute HTTP GET request."""
        import time
        start = time.time()
        
        try:
            response = requests.get(
                url,
                headers=headers or {},
                timeout=timeout,
                verify=True
            )
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS if response.status_code < 400 else ExecutionStatus.FAILED,
                output={
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text
                },
                exit_code=response.status_code,
                duration_ms=(time.time() - start) * 1000
            )
        except requests.Timeout:
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                error=f"Request timed out after {timeout}s",
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_http_post(self, url: str, data: Any = None, 
                          headers: Dict[str, str] = None,
                          timeout: int = 30) -> ExecutionResult:
        """Execute HTTP POST request."""
        import time
        start = time.time()
        
        try:
            if isinstance(data, dict):
                headers = {**{"Content-Type": "application/json"}, **(headers or {})}
                json_data = json.dumps(data)
            else:
                json_data = data
            
            response = requests.post(
                url,
                data=json_data,
                headers=headers or {},
                timeout=timeout,
                verify=True
            )
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS if response.status_code < 400 else ExecutionStatus.FAILED,
                output={
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text
                },
                exit_code=response.status_code,
                duration_ms=(time.time() - start) * 1000
            )
        except requests.Timeout:
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                error=f"Request timed out after {timeout}s",
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )
    
    def execute_database_query(self, query: str, params: tuple = ()) -> ExecutionResult:
        """Execute a database query (SQLite for now)."""
        import time
        import sqlite3
        start = time.time()
        
        try:
            # Use a local SQLite database for safety
            db_path = os.path.join(os.getcwd(), "guardrail.db")
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if query.strip().upper().startswith("SELECT"):
                rows = cursor.fetchall()
                output = [dict(row) for row in rows]
            else:
                conn.commit()
                output = {"rows_affected": cursor.rowcount}
            
            conn.close()
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                output=output,
                duration_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration_ms=(time.time() - start) * 1000
            )


def create_tool_executor(action_type: str, executor: RealToolExecutor):
    """Create a tool executor function for a specific action type."""
    
    def executor_fn(step) -> Dict[str, Any]:
        """Execute a step based on its action type."""
        action = step.action_type.lower()
        resource = step.resource
        params = getattr(step, 'parameters', {}) or {}
        
        if action == "file_read":
            result = executor.execute_file_read(resource)
        elif action == "file_write":
            content = params.get("content", "")
            result = executor.execute_file_write(resource, content)
        elif action == "file_delete":
            result = executor.execute_file_delete(resource)
        elif action == "shell_command":
            result = executor.execute_shell_command(resource)
        elif action == "http_get":
            result = executor.execute_http_get(resource, params.get("headers"))
        elif action == "http_post":
            result = executor.execute_http_post(resource, params.get("data"), params.get("headers"))
        elif action == "database_query":
            result = executor.execute_database_query(resource, tuple(params.get("params", [])))
        else:
            result = ExecutionResult(
                status=ExecutionStatus.FAILED,
                error=f"Unknown action type: {action}"
            )
        
        return {
            "status": result.status.value,
            "step_id": step.id,
            "action": step.action_type,
            "resource": step.resource,
            "result": result.output,
            "error": result.error,
            "duration_ms": result.duration_ms
        }
    
    return executor_fn


# Backward compatibility: mock executor for testing
def mock_executor(step) -> Dict[str, Any]:
    """Mock executor for testing."""
    return {
        "status": "executed",
        "step_id": step.id,
        "action": step.action_type,
        "resource": step.resource,
        "result": f"Mock execution of {step.action_type} on {step.resource}",
    }