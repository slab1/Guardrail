"""PEP-Exec: Policy Enforcement Point for Execution (Firecracker microVMs)."""
import subprocess
import json
import tempfile
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from guardrail.pep_framework import BasePEP, PEPRequest, PEPResponse, PEPType, register_pep


@dataclass
class MicroVMConfig:
    """Configuration for a Firecracker microVM."""
    vm_id: str
    cpu_count: int = 1
    memory_mib: int = 128
    kernel_image: str = "/opt/firecracker/vmlinux.bin"
    rootfs_image: str = "/opt/firecracker/ubuntu-22.04.ext4"
    network_interface: str = "tap0"
    ip_address: str = "172.16.0.2"
    gateway_ip: str = "172.16.0.1"
    mac_address: str = "02:FC:00:00:00:01"
    jailer_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of an execution."""
    vm_id: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    resources_used: Dict[str, Any] = field(default_factory=dict)


class FirecrackerManager:
    """Manages Firecracker microVMs for secure execution."""
    
    def __init__(self, base_path: str = "/tmp/guardrail_firecracker"):
        self.base_path = base_path
        self.vms: Dict[str, MicroVMConfig] = {}
        self.running_vms: Dict[str, subprocess.Popen] = {}
        os.makedirs(base_path, exist_ok=True)
    
    def create_vm(self, config: MicroVMConfig) -> PEPResponse:
        """Create a new microVM configuration."""
        vm_dir = os.path.join(self.base_path, config.vm_id)
        os.makedirs(vm_dir, exist_ok=True)
        
        # Store config
        self.vms[config.vm_id] = config
        
        config_path = os.path.join(vm_dir, "firecracker_config.json")
        # Create minimal config file
        with open(config_path, "w") as f:
            json.dump({"vm_id": config.vm_id}, f)
        
        return PEPResponse(
            success=True,
            result={"vm_id": config.vm_id, "config_path": config_path}
        )
    
    def start_vm(self, vm_id: str) -> PEPResponse:
        """Start a microVM."""
        if vm_id not in self.vms:
            return PEPResponse(
                success=False,
                error=f"VM not found: {vm_id}"
            )
        
        if vm_id in self.running_vms:
            return PEPResponse(
                success=False,
                error=f"VM already running: {vm_id}"
            )
        
        config = self.vms[vm_id]
        vm_dir = os.path.join(self.base_path, vm_id)
        config_path = os.path.join(vm_dir, "firecracker_config.json")
        socket_path = os.path.join(vm_dir, "firecracker.socket")
        log_path = os.path.join(vm_dir, "firecracker.log")
        
        # Firecracker command
        cmd = [
            "firecracker",
            "--api-sock", socket_path,
            "--config-file", config_path,
            "--log-path", log_path,
            "--level", "Info",
            "--show-level",
            "--show-log-origin"
        ]
        
        try:
            # Start Firecracker process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            
            self.running_vms[vm_id] = process
            
            # Wait for VM to be ready (simplified)
            time.sleep(2)
            
            return PEPResponse(
                success=True,
                result={"vm_id": vm_id, "pid": process.pid, "socket": socket_path}
            )
        except FileNotFoundError:
            return PEPResponse(
                success=False,
                error="Firecracker binary not found. Install firecracker."
            )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"Failed to start VM: {str(e)}"
            )
    
    def execute_command(self, vm_id: str, command: str, timeout: int = 30) -> PEPResponse:
        """Execute a command inside a running microVM via SSH."""
        if vm_id not in self.running_vms:
            return PEPResponse(
                success=False,
                error=f"VM not running: {vm_id}"
            )
        
        config = self.vms[vm_id]
        
        # Execute via SSH (requires SSH setup in the VM)
        # This is a simplified mock - in production you'd use SSH or vsock
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            f"root@{config.ip_address}",
            command
        ]
        
        start_time = time.time()
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            duration_ms = int((time.time() - start_time) * 1000)
            
            return PEPResponse(
                success=result.returncode == 0,
                result=ExecutionResult(
                    vm_id=vm_id,
                    exit_code=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    duration_ms=duration_ms,
                ).__dict__,
                error=result.stderr if result.returncode != 0 else None
            )
        except subprocess.TimeoutExpired:
            return PEPResponse(
                success=False,
                error=f"Command timed out after {timeout}s"
            )
        except Exception as e:
            return PEPResponse(
                success=False,
                error=f"Execution error: {str(e)}"
            )
    
    def stop_vm(self, vm_id: str) -> PEPResponse:
        """Stop a microVM."""
        if vm_id not in self.running_vms:
            return PEPResponse(
                success=False,
                error=f"VM not running: {vm_id}"
            )
        
        process = self.running_vms[vm_id]
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        
        del self.running_vms[vm_id]
        
        return PEPResponse(
            success=True,
            result={"vm_id": vm_id, "stopped": True}
        )
    
    def cleanup_vm(self, vm_id: str) -> PEPResponse:
        """Clean up VM resources."""
        if vm_id in self.running_vms:
            self.stop_vm(vm_id)
        
        if vm_id in self.vms:
            vm_dir = os.path.join(self.base_path, vm_id)
            import shutil
            if os.path.exists(vm_dir):
                shutil.rmtree(vm_dir)
            del self.vms[vm_id]
        
        return PEPResponse(
            success=True,
            result={"vm_id": vm_id, "cleaned_up": True}
        )


class PepExec(BasePEP):
    """PEP-Exec: Policy Enforcement Point for Execution in Firecracker microVMs."""
    
    def __init__(self, manager: Optional[FirecrackerManager] = None):
        super().__init__(PEPType.EXEC)
        self.manager = manager or FirecrackerManager()
        
        # Define allowed actions
        self.allowed_actions = {
            "vm_create", "vm_start", "vm_execute", "vm_stop", "vm_cleanup",
            "shell_command", "shell_pipe", "shell_exec",
        }
        self.action_categories = {
            "vm_create": "write",
            "vm_start": "execute",
            "vm_execute": "execute",
            "vm_stop": "execute",
            "vm_cleanup": "write",
            "shell_command": "execute",
            "shell_pipe": "execute",
            "shell_exec": "execute",
        }
    
    def enforce(self, request: PEPRequest) -> PEPResponse:
        """Enforce execution policy."""
        # Validate token
        if not self.validate_token(request):
            return self.create_denied_response(request, "Invalid or expired token")
        
        # Check if action is allowed
        if not self.check_action_allowed(request.action):
            return self.create_denied_response(request, f"Action not allowed: {request.action}")
        
        try:
            if request.action == "vm_create":
                config_data = request.metadata.get("config", {})
                # Extract vm_id from config_data to avoid duplicate
                vm_id = config_data.pop("vm_id", str(uuid.uuid4()))
                config = MicroVMConfig(vm_id=vm_id, **config_data)
                return self.manager.create_vm(config)
            
            elif request.action == "vm_start":
                vm_id = request.resource
                return self.manager.start_vm(vm_id)
            
            elif request.action == "vm_execute":
                vm_id = request.resource
                command = request.metadata.get("command", "")
                timeout = request.metadata.get("timeout", 30)
                return self.manager.execute_command(vm_id, command, timeout)
            
            elif request.action == "vm_stop":
                vm_id = request.resource
                return self.manager.stop_vm(vm_id)
            
            elif request.action == "vm_cleanup":
                vm_id = request.resource
                return self.manager.cleanup_vm(vm_id)
            
            elif request.action in ("shell_command", "shell_pipe", "shell_exec"):
                # For direct shell commands, create a temporary VM
                vm_id = f"temp_{uuid.uuid4().hex[:8]}"
                config = MicroVMConfig(vm_id=vm_id)
                
                create_resp = self.manager.create_vm(config)
                if not create_resp.success:
                    return create_resp
                
                start_resp = self.manager.start_vm(vm_id)
                if not start_resp.success:
                    self.manager.cleanup_vm(vm_id)
                    return start_resp
                
                command = request.metadata.get("command", request.resource)
                exec_resp = self.manager.execute_command(vm_id, command)
                
                # Cleanup
                self.manager.stop_vm(vm_id)
                self.manager.cleanup_vm(vm_id)
                
                return exec_resp
            
            else:
                return self.create_denied_response(request, f"Unknown action: {request.action}")
        
        except Exception as e:
            return self.create_denied_response(request, f"Execution error: {str(e)}")


# Convenience function
def create_pep_exec(base_path: str = "/tmp/guardrail_firecracker") -> PepExec:
    """Create and register a PepExec instance."""
    manager = FirecrackerManager(base_path)
    pep_exec = PepExec(manager)
    register_pep(pep_exec)
    return pep_exec


# ----------------------------------------------------------------------
# Example usage (mock - won't work without Firecracker installed)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("PEP-Exec module loaded. Firecracker binary required for actual execution.")
    print("This is a mock demonstration.")
    
    # Show what the API looks like
    from guardrail.token_service import create_step_token
    
    token = create_step_token("plan_001", "step_001", "Execute command", "coding", "user1", 2)
    
    request = PEPRequest(
        pep_type=PEPType.EXEC,
        token=token,
        plan_id="plan_001",
        step_id="step_001",
        agent_class="coding",
        user_id="user1",
        autonomy_level=2,
        action="shell_command",
        resource="ls -la",
        metadata={"command": "ls -la"}
    )
    
    print(f"Request: {request}")
    print("Would execute in Firecracker microVM if available.")