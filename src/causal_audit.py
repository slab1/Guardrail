"""eBPF Causal Audit Subsystem (AgentLoupe-style).

This module provides kernel-level causal labeling for agent actions,
enabling full attribution of system calls to specific agent intents.
"""
import os
import json
import time
import hashlib
import threading
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class AuditEventType(Enum):
    """Types of audited events."""
    SYSCALL = "syscall"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"
    PROCESS_EXEC = "process_exec"
    CAPABILITY_CHECK = "capability_check"
    TOKEN_VALIDATION = "token_validation"
    CONSENT_DECISION = "consent_decision"
    PLAN_EXECUTION = "plan_execution"


@dataclass
class CausalLabel:
    """Causal label linking an event to its originating agent intent."""
    label_id: str
    plan_id: str
    step_id: str
    intent: str
    agent_class: str
    user_id: str
    autonomy_level: int
    timestamp: int
    parent_label_id: Optional[str] = None  # For nested causality
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEvent:
    """Single audit event with causal label."""
    event_id: str
    event_type: AuditEventType
    causal_label: CausalLabel
    syscall: Optional[str] = None
    pid: int = 0
    tid: int = 0
    comm: str = ""
    args: Dict[str, Any] = field(default_factory=dict)
    result: Any = None
    duration_ns: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class CausalAuditLogger:
    """Causal audit logger with hash-chained event log."""
    
    def __init__(self, log_path: str = "/var/log/guardrail/audit.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.lock = threading.Lock()
        self.last_hash = b"0" * 32  # Genesis hash
        self.event_count = 0
        self.labels: Dict[str, CausalLabel] = {}
        self.label_to_events: Dict[str, List[str]] = defaultdict(list)
        self.plan_to_labels: Dict[str, List[str]] = defaultdict(list)
    
    def _compute_hash(self, event: AuditEvent) -> bytes:
        """Compute hash for hash-chaining."""
        event_data = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "causal_label_id": event.causal_label.label_id,
            "syscall": event.syscall,
            "pid": event.pid,
            "tid": event.tid,
            "comm": event.comm,
            "args": event.args,
            "result": str(event.result),
            "duration_ns": event.duration_ns,
            "prev_hash": self.last_hash.hex(),
            "timestamp": event.causal_label.timestamp,
        }
        data = json.dumps(event_data, sort_keys=True).encode()
        return hashlib.sha256(data).digest()
    
    def create_causal_label(
        self,
        plan_id: str,
        step_id: str,
        intent: str,
        agent_class: str,
        user_id: str,
        autonomy_level: int,
        parent_label_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CausalLabel:
        """Create a new causal label."""
        label_id = hashlib.sha256(
            f"{plan_id}{step_id}{intent}{time.time()}".encode()
        ).hexdigest()[:16]
        
        label = CausalLabel(
            label_id=label_id,
            plan_id=plan_id,
            step_id=step_id,
            intent=intent,
            agent_class=agent_class,
            user_id=user_id,
            autonomy_level=autonomy_level,
            timestamp=int(time.time() * 1_000_000),  # microseconds
            parent_label_id=parent_label_id,
            metadata=metadata or {},
        )
        
        self.labels[label_id] = label
        self.plan_to_labels[plan_id].append(label_id)
        return label
    
    def log_event(
        self,
        event_type: AuditEventType,
        causal_label: CausalLabel,
        syscall: Optional[str] = None,
        pid: Optional[int] = None,
        tid: Optional[int] = None,
        comm: str = "",
        args: Optional[Dict[str, Any]] = None,
        result: Any = None,
        duration_ns: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Log an audit event with causal label."""
        event_id = hashlib.sha256(
            f"{causal_label.label_id}{event_type.value}{time.time_ns()}".encode()
        ).hexdigest()[:16]
        
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            causal_label=causal_label,
            syscall=syscall,
            pid=pid or os.getpid(),
            tid=tid or threading.get_ident(),
            comm=comm,
            args=args or {},
            result=result,
            duration_ns=duration_ns,
            metadata=metadata or {},
        )
        
        # Compute hash chain
        event_hash = self._compute_hash(event)
        
        # Write to log
        with self.lock:
            log_entry = {
                "event": {
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "causal_label_id": event.causal_label.label_id,
                    "syscall": event.syscall,
                    "pid": event.pid,
                    "tid": event.tid,
                    "comm": event.comm,
                    "args": event.args,
                    "result": str(event.result),
                    "duration_ns": event.duration_ns,
                    "metadata": event.metadata,
                },
                "hash": event_hash.hex(),
                "prev_hash": self.last_hash.hex(),
            }
            
            with open(self.log_path, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            
            self.last_hash = event_hash
            self.event_count += 1
            self.label_to_events[causal_label.label_id].append(event_id)
        
        return event
    
    def get_events_for_label(self, label_id: str) -> List[str]:
        """Get event IDs for a causal label."""
        return self.label_to_events.get(label_id, [])
    
    def get_labels_for_plan(self, plan_id: str) -> List[str]:
        """Get label IDs for a plan."""
        return self.plan_to_labels.get(plan_id, [])
    
    def get_causal_chain(self, label_id: str) -> List[CausalLabel]:
        """Get full causal chain from label to root."""
        chain = []
        current_id = label_id
        while current_id and current_id in self.labels:
            label = self.labels[current_id]
            chain.append(label)
            current_id = label.parent_label_id
        return chain
    
    def verify_integrity(self) -> bool:
        """Verify hash chain integrity."""
        try:
            with open(self.log_path, "r") as f:
                prev_hash = b"0" * 32
                for line in f:
                    entry = json.loads(line)
                    curr_hash = bytes.fromhex(entry["hash"])
                    if entry["prev_hash"] != prev_hash.hex():
                        return False
                    prev_hash = curr_hash
            return True
        except Exception:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        return {
            "total_events": self.event_count,
            "total_labels": len(self.labels),
            "total_plans": len(self.plan_to_labels),
            "log_file": self.log_path,
            "integrity_verified": self.verify_integrity(),
        }


class EBPFAuditProbe:
    """eBPF probe manager for kernel-level causal auditing.
    
    This is a mock implementation. In production, this would load
    eBPF programs using libbpf or bpftrace.
    """
    
    def __init__(self, logger: CausalAuditLogger):
        self.logger = logger
        self.active = False
        self.attached_programs: List[str] = []
    
    def attach_syscall_probes(self, syscalls: Optional[List[str]] = None) -> bool:
        """Attach eBPF probes to syscalls."""
        if syscalls is None:
            syscalls = [
                "open", "openat", "read", "write", "close",
                "execve", "execveat", "fork", "clone", "vfork",
                "connect", "sendto", "recvfrom", "bind", "listen",
                "mmap", "munmap", "mprotect", "ptrace",
                "capget", "capset", "seccomp",
            ]
        
        self.attached_programs = [f"sys_{sc}" for sc in syscalls]
        self.active = True
        
        # In production, this would load eBPF programs
        # For now, we just simulate
        return True
    
    def detach_probes(self):
        """Detach all eBPF probes."""
        self.attached_programs = []
        self.active = False
    
    def on_syscall(self, syscall: str, pid: int, tid: int, args: Dict, result: Any, duration_ns: int):
        """Callback for syscall events (called from eBPF)."""
        # In production, this would be called from eBPF context
        # We need to find the causal label for this PID/TID
        # This is simplified - real implementation would use a PID->label map
        pass


# Global audit logger instance
_audit_logger: Optional[CausalAuditLogger] = None
_ebpf_probe: Optional[EBPFAuditProbe] = None


def get_audit_logger() -> CausalAuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = CausalAuditLogger()
    return _audit_logger


def get_ebpf_probe() -> EBPFAuditProbe:
    """Get the global eBPF probe instance."""
    global _ebpf_probe
    if _ebpf_probe is None:
        _ebpf_probe = EBPFAuditProbe(get_audit_logger())
    return _ebpf_probe


def create_causal_label(
    plan_id: str,
    step_id: str,
    intent: str,
    agent_class: str,
    user_id: str,
    autonomy_level: int,
    parent_label_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> CausalLabel:
    """Convenience function to create a causal label."""
    return get_audit_logger().create_causal_label(
        plan_id, step_id, intent, agent_class, user_id, autonomy_level,
        parent_label_id, metadata
    )


def log_audit_event(
    event_type: AuditEventType,
    causal_label: CausalLabel,
    **kwargs
) -> AuditEvent:
    """Convenience function to log an audit event."""
    return get_audit_logger().log_event(event_type, causal_label, **kwargs)


def start_ebpf_auditing(syscalls: Optional[List[str]] = None) -> bool:
    """Start eBPF auditing."""
    probe = get_ebpf_probe()
    return probe.attach_syscall_probes(syscalls)


def stop_ebpf_auditing():
    """Stop eBPF auditing."""
    probe = get_ebpf_probe()
    probe.detach_probes()


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    logger = CausalAuditLogger("/tmp/guardrail_audit.log")
    probe = EBPFAuditProbe(logger)
    
    # Create causal label for a plan step
    label = logger.create_causal_label(
        plan_id="plan_001",
        step_id="step_001",
        intent="Write configuration file",
        agent_class="coding",
        user_id="user123",
        autonomy_level=2,
    )
    print(f"Created causal label: {label.label_id}")
    
    # Log some events
    event1 = logger.log_event(
        AuditEventType.SYSCALL,
        label,
        syscall="openat",
        args={"path": "/etc/config.yaml", "flags": "O_WRONLY|O_CREAT"},
        result=3,  # file descriptor
        duration_ns=12500,
    )
    print(f"Logged syscall event: {event1.event_id}")
    
    event2 = logger.log_event(
        AuditEventType.FILE_ACCESS,
        label,
        syscall="write",
        args={"fd": 3, "size": 42},
        result=42,
        duration_ns=8900,
    )
    print(f"Logged file access event: {event2.event_id}")
    
    # Get causal chain
    chain = logger.get_causal_chain(label.label_id)
    print(f"Causal chain length: {len(chain)}")
    
    # Verify integrity
    print(f"Log integrity: {logger.verify_integrity()}")
    
    # Stats
    print(f"Stats: {logger.get_stats()}")