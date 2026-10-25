"""Disaster Recovery and Backup Procedures for Guardrail.

This module provides comprehensive disaster recovery capabilities including:
- Automated backup and restore of audit logs, LSFS data, and configuration
- Cross-region replication for high availability
- Point-in-time recovery (PITR) for audit logs
- Failover procedures and health checks
"""
import time
import json
import uuid
import hashlib
import shutil
import threading
import subprocess
from typing import Any, Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
import tarfile
import gzip
import os


class BackupType(Enum):
    """Types of backups."""
    FULL = "full"
    INCREMENTAL = "incremental"
    SNAPSHOT = "snapshot"


class BackupStatus(Enum):
    """Backup operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class RecoveryPointObjective(Enum):
    """RPO tiers."""
    RPO_ZERO = "zero"      # Synchronous replication
    RPO_MINUTES = "minutes"  # Near real-time
    RPO_HOURS = "hours"    # Hourly snapshots
    RPO_DAYS = "days"      # Daily backups


@dataclass
class BackupConfig:
    """Configuration for backup operations."""
    backup_type: BackupType = BackupType.FULL
    source_paths: List[str] = field(default_factory=list)
    destination: str = "/backup/guardrail"
    retention_days: int = 30
    compression: bool = True
    encryption: bool = False
    encryption_key: Optional[str] = None
    schedule: str = "0 2 * * *"  # Daily at 2 AM (cron format)
    rpo: RecoveryPointObjective = RecoveryPointObjective.RPO_HOURS
    max_parallel_jobs: int = 2
    notify_on_failure: bool = True
    notify_on_success: bool = False


@dataclass
class BackupRecord:
    """Record of a backup operation."""
    backup_id: str
    config: BackupConfig
    status: BackupStatus = BackupStatus.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    size_bytes: int = 0
    file_count: int = 0
    checksum: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecoveryPlan:
    """Disaster recovery plan."""
    plan_id: str
    name: str
    description: str
    trigger_conditions: List[str] = field(default_factory=list)
    recovery_steps: List[Dict[str, Any]] = field(default_factory=list)
    rto_seconds: int = 3600  # Recovery Time Objective
    rpo: RecoveryPointObjective = RecoveryPointObjective.RPO_HOURS
    responsible_team: str = "platform"
    last_tested: Optional[float] = None
    test_results: List[Dict[str, Any]] = field(default_factory=list)


class BackupManager:
    """Manages backup operations for Guardrail components."""
    
    def __init__(self, config: BackupConfig):
        self.config = config
        self.backup_records: Dict[str, BackupRecord] = {}
        self.lock = threading.RLock()
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
    
    def create_backup(self, backup_type: Optional[BackupType] = None) -> BackupRecord:
        """Create a new backup."""
        backup_type = backup_type or self.config.backup_type
        backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        record = BackupRecord(
            backup_id=backup_id,
            config=self.config,
            status=BackupStatus.IN_PROGRESS,
            started_at=time.time(),
        )
        
        with self.lock:
            self.backup_records[backup_id] = record
        
        try:
            # Perform backup
            self._perform_backup(record)
            
            record.status = BackupStatus.COMPLETED
            record.completed_at = time.time()
            
        except Exception as e:
            record.status = BackupStatus.FAILED
            record.error_message = str(e)
            record.completed_at = time.time()
            raise
        
        finally:
            with self.lock:
                self.backup_records[backup_id] = record
        
        return record
    
    def _perform_backup(self, record: BackupRecord):
        """Execute the actual backup."""
        dest_path = Path(self.config.destination) / record.backup_id
        dest_path.mkdir(parents=True, exist_ok=True)
        
        total_size = 0
        file_count = 0
        
        # Create tar archive
        archive_name = f"guardrail_backup_{record.backup_id}.tar"
        if self.config.compression:
            archive_name += ".gz"
        
        archive_path = dest_path / archive_name
        
        mode = "w:gz" if self.config.compression else "w"
        
        with tarfile.open(archive_path, mode) as tar:
            for source_path in self.config.source_paths:
                source = Path(source_path)
                if source.exists():
                    if source.is_file():
                        tar.add(source, arcname=source.name)
                        file_count += 1
                        total_size += source.stat().st_size
                    elif source.is_dir():
                        for file_path in source.rglob("*"):
                            if file_path.is_file():
                                tar.add(file_path, arcname=file_path.relative_to(source.parent))
                                file_count += 1
                                total_size += file_path.stat().st_size
        
        # Calculate checksum
        record.checksum = self._calculate_checksum(archive_path)
        record.size_bytes = archive_path.stat().st_size
        record.file_count = file_count
        
        # Encrypt if configured
        if self.config.encryption and self.config.encryption_key:
            self._encrypt_file(archive_path, self.config.encryption_key)
        
        # Clean up old backups
        self._cleanup_old_backups()
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _encrypt_file(self, file_path: Path, key: str):
        """Encrypt a file using AES-256."""
        # In production, use proper encryption (cryptography library)
        # This is a placeholder
        pass
    
    def _cleanup_old_backups(self):
        """Remove backups older than retention period."""
        cutoff_time = time.time() - (self.config.retention_days * 86400)
        
        for backup_id, record in list(self.backup_records.items()):
            if record.completed_at and record.completed_at < cutoff_time:
                # Delete backup files
                backup_dir = Path(self.config.destination) / backup_id
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                del self.backup_records[backup_id]
    
    def restore_backup(self, backup_id: str, target_path: Optional[str] = None) -> bool:
        """Restore from a backup."""
        with self.lock:
            record = self.backup_records.get(backup_id)
        
        if not record:
            raise ValueError(f"Backup not found: {backup_id}")
        
        if record.status != BackupStatus.COMPLETED:
            raise ValueError(f"Backup not completed: {backup_id}")
        
        # Verify checksum
        archive_path = Path(self.config.destination) / backup_id / f"guardrail_backup_{backup_id}.tar.gz"
        if not archive_path.exists():
            archive_path = Path(self.config.destination) / backup_id / f"guardrail_backup_{backup_id}.tar"
        
        if not archive_path.exists():
            raise ValueError(f"Backup archive not found: {archive_path}")
        
        current_checksum = self._calculate_checksum(archive_path)
        if current_checksum != record.checksum:
            raise ValueError("Backup checksum mismatch - data may be corrupted")
        
        # Extract archive
        target = Path(target_path) if target_path else Path("/")
        target.mkdir(parents=True, exist_ok=True)
        
        mode = "r:gz" if self.config.compression else "r"
        
        with tarfile.open(archive_path, mode) as tar:
            tar.extractall(target)
        
        return True
    
    def list_backups(self, status: Optional[str] = None) -> List[BackupRecord]:
        """List all backups, optionally filtered by status."""
        with self.lock:
            records = list(self.backup_records.values())
        
        if status:
            records = [r for r in records if r.status.value == status]
        
        return sorted(records, key=lambda r: r.started_at or 0, reverse=True)
    
    def get_backup(self, backup_id: str) -> Optional[BackupRecord]:
        """Get a specific backup record."""
        with self.lock:
            return self.backup_records.get(backup_id)
    
    def start_scheduler(self):
        """Start the backup scheduler."""
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the backup scheduler."""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
    
    def _scheduler_loop(self):
        """Main scheduler loop."""
        while self.running:
            try:
                # Simple cron-like scheduling (simplified)
                # In production, use a proper scheduler like APScheduler
                now = datetime.now()
                if now.hour == 2 and now.minute == 0:  # 2 AM
                    self.create_backup()
            except Exception:
                pass
            time.sleep(60)  # Check every minute


class ReplicationManager:
    """Manages cross-region replication for high availability."""
    
    def __init__(self, primary_region: str, replica_regions: List[str]):
        self.primary_region = primary_region
        self.replica_regions = replica_regions
        self.replication_status: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
    
    def replicate_data(self, source_path: str, data: bytes) -> Dict[str, bool]:
        """Replicate data to all replica regions."""
        results = {}
        
        for region in self.replica_regions:
            try:
                # In production, this would use actual replication (S3 CRR, etc.)
                # This is a simulation
                success = self._replicate_to_region(region, source_path, data)
                results[region] = success
                
                with self.lock:
                    self.replication_status[region] = {
                        "last_sync": time.time(),
                        "status": "synced" if success else "failed",
                        "lag_seconds": 0 if success else None,
                    }
            except Exception as e:
                results[region] = False
                with self.lock:
                    self.replication_status[region] = {
                        "last_sync": time.time(),
                        "status": "error",
                        "error": str(e),
                    }
        
        return results
    
    def _replicate_to_region(self, region: str, source_path: str, data: bytes) -> bool:
        """Replicate data to a specific region."""
        # Simulate network latency
        time.sleep(0.01)
        # In production, this would use actual replication
        return True
    
    def get_replication_lag(self, region: str) -> Optional[float]:
        """Get replication lag for a region in seconds."""
        with self.lock:
            status = self.replication_status.get(region)
            if status and status.get("last_sync"):
                return time.time() - status["last_sync"]
        return None
    
    def get_replication_status(self) -> Dict[str, Dict[str, Any]]:
        """Get replication status for all regions."""
        with self.lock:
            return dict(self.replication_status)


class FailoverManager:
    """Manages failover procedures for high availability."""
    
    def __init__(self, regions: List[str]):
        self.regions = regions
        self.current_primary = regions[0] if regions else None
        self.region_health: Dict[str, Dict[str, Any]] = {}
        self.failover_history: List[Dict[str, Any]] = []
        self.lock = threading.RLock()
        self.auto_failover = True
    
    def register_region(self, region: str, endpoint: str, health_check: Callable[[], bool]):
        """Register a region with its health check."""
        with self.lock:
            self.region_health[region] = {
                "endpoint": endpoint,
                "health_check": health_check,
                "healthy": True,
                "last_check": time.time(),
                "failure_count": 0,
            }
    
    def check_region_health(self, region: str) -> bool:
        """Check health of a specific region."""
        with self.lock:
            health_info = self.region_health.get(region)
        
        if not health_info:
            return False
        
        try:
            healthy = health_info["health_check"]()
            with self.lock:
                health_info["healthy"] = healthy
                health_info["last_check"] = time.time()
                if healthy:
                    health_info["failure_count"] = 0
                else:
                    health_info["failure_count"] += 1
            return healthy
        except Exception:
            with self.lock:
                health_info["healthy"] = False
                health_info["last_check"] = time.time()
                health_info["failure_count"] += 1
            return False
    
    def check_all_regions(self) -> Dict[str, bool]:
        """Check health of all regions."""
        results = {}
        for region in self.regions:
            results[region] = self.check_region_health(region)
        return results
    
    def initiate_failover(self, failed_region: str, new_primary: Optional[str] = None) -> bool:
        """Initiate failover from failed region to new primary."""
        with self.lock:
            if failed_region not in self.regions:
                return False
            
            if failed_region == self.current_primary:
                if new_primary is None:
                    # Auto-select new primary from healthy regions
                    for region in self.regions:
                        if region != failed_region and self.region_health.get(region, {}).get("healthy", False):
                            new_primary = region
                            break
                
                if new_primary is None:
                    return False  # No healthy region available
                
                old_primary = self.current_primary
                self.current_primary = new_primary
                
                self.failover_history.append({
                    "timestamp": time.time(),
                    "from_region": old_primary,
                    "to_region": new_primary,
                    "reason": f"Failover from {failed_region}",
                    "trigger": "automatic" if self.auto_failover else "manual",
                })
                
                return True
        
        return False
    
    def get_current_primary(self) -> Optional[str]:
        """Get the current primary region."""
        with self.lock:
            return self.current_primary
    
    def get_region_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all regions."""
        with self.lock:
            return dict(self.region_health)
    
    def get_failover_history(self) -> List[Dict[str, Any]]:
        """Get failover history."""
        with self.lock:
            return list(self.failover_history)


class DisasterRecoveryOrchestrator:
    """Orchestrates disaster recovery operations."""
    
    def __init__(
        self,
        backup_manager: BackupManager,
        replication_manager: ReplicationManager,
        failover_manager: FailoverManager,
    ):
        self.backup_manager = backup_manager
        self.replication_manager = replication_manager
        self.failover_manager = failover_manager
        self.recovery_plans: Dict[str, RecoveryPlan] = {}
        self.active_recovery: Optional[str] = None
    
    def register_recovery_plan(self, plan: RecoveryPlan):
        """Register a disaster recovery plan."""
        self.recovery_plans[plan.plan_id] = plan
    
    def execute_recovery(self, plan_id: str, trigger: str = "manual") -> bool:
        """Execute a disaster recovery plan."""
        if self.active_recovery:
            raise RuntimeError("Another recovery is already in progress")
        
        plan = self.recovery_plans.get(plan_id)
        if not plan:
            raise ValueError(f"Recovery plan not found: {plan_id}")
        
        self.active_recovery = plan_id
        start_time = time.time()
        
        try:
            for step in plan.recovery_steps:
                step_name = step.get("name", "unknown")
                action = step.get("action")
                
                if action == "failover":
                    target = step.get("target_region")
                    if not self.failover_manager.initiate_failover(
                        self.failover_manager.current_primary, target
                    ):
                        raise RuntimeError(f"Failover to {target} failed")
                
                elif action == "restore_backup":
                    backup_id = step.get("backup_id")
                    target_path = step.get("target_path")
                    if not self.backup_manager.restore_backup(backup_id, target_path):
                        raise RuntimeError(f"Backup restore failed: {backup_id}")
                
                elif action == "verify_replication":
                    region = step.get("region")
                    lag = self.replication_manager.get_replication_lag(region or "")
                    if lag is None or lag > 300:  # 5 minutes max lag
                        raise RuntimeError(f"Replication lag too high for {region}")
                
                elif action == "health_check":
                    region = step.get("region")
                    if not self.failover_manager.check_region_health(region or ""):
                        raise RuntimeError(f"Health check failed for {region}")
                
                elif action == "notify":
                    message = step.get("message", "Recovery step completed")
                    self._send_notification(message)
            
            plan.last_tested = time.time()
            plan.test_results.append({
                "timestamp": time.time(),
                "trigger": "manual",
                "duration_seconds": time.time() - start_time,
                "success": True,
            })
            
            return True
            
        except Exception as e:
            plan.test_results.append({
                "timestamp": time.time(),
                "trigger": "manual",
                "duration_seconds": time.time() - start_time,
                "success": False,
                "error": str(e),
            })
            raise
        finally:
            self.active_recovery = None
    
    def _send_notification(self, message: str):
        """Send notification (placeholder)."""
        # In production, integrate with PagerDuty, Slack, email, etc.
        pass
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """Get current disaster recovery status."""
        return {
            "active_recovery": self.active_recovery,
            "current_primary": self.failover_manager.get_current_primary(),
            "region_health": self.failover_manager.get_region_health(),
            "replication_status": self.replication_manager.get_replication_status(),
            "recent_backups": self.backup_manager.list_backups()[:5],
        }


# Convenience functions
def create_backup_manager(config: Optional[BackupConfig] = None) -> BackupManager:
    """Create a backup manager with default config."""
    if config is None:
        config = BackupConfig(
            source_paths=[
                "/var/log/guardrail",
                "/var/lib/guardrail/lsfs",
                "/etc/guardrail",
            ],
            destination="/backup/guardrail",
            retention_days=30,
        )
    return BackupManager(config)


def create_replication_manager(
    primary_region: str = "us-east-1",
    replica_regions: Optional[List[str]] = None
) -> ReplicationManager:
    """Create a replication manager."""
    if replica_regions is None:
        replica_regions = ["us-west-2", "eu-west-1"]
    return ReplicationManager(primary_region, replica_regions)


def create_failover_manager(regions: Optional[List[str]] = None) -> FailoverManager:
    """Create a failover manager."""
    if regions is None:
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
    return FailoverManager(regions)


def create_disaster_recovery_orchestrator(
    backup_manager: Optional[BackupManager] = None,
    replication_manager: Optional[ReplicationManager] = None,
    failover_manager: Optional[FailoverManager] = None,
) -> DisasterRecoveryOrchestrator:
    """Create a disaster recovery orchestrator with default components."""
    if backup_manager is None:
        backup_manager = create_backup_manager()
    if replication_manager is None:
        replication_manager = create_replication_manager()
    if failover_manager is None:
        failover_manager = create_failover_manager()
    
    return DisasterRecoveryOrchestrator(backup_manager, replication_manager, failover_manager)


# Example recovery plan
DEFAULT_RECOVERY_PLAN = RecoveryPlan(
    plan_id="dr_plan_001",
    name="Primary Region Failure",
    description="Failover to secondary region when primary fails",
    trigger_conditions=[
        "primary_region_unhealthy",
        "replication_lag_exceeded",
        "manual_trigger",
    ],
    recovery_steps=[
        {"name": "failover_to_secondary", "action": "failover", "target_region": "us-west-2"},
        {"name": "verify_replication", "action": "verify_replication", "region": "us-west-2"},
        {"name": "health_check", "action": "health_check", "region": "us-west-2"},
        {"name": "notify_team", "action": "notify", "message": "Failover to us-west-2 completed"},
    ],
    rto_seconds=1800,  # 30 minutes
    rpo=RecoveryPointObjective.RPO_MINUTES,
)


if __name__ == "__main__":
    # Example usage
    config = BackupConfig(
        source_paths=["/var/log/guardrail", "/var/lib/guardrail/lsfs"],
        destination="/tmp/guardrail_backups",
        retention_days=7,
    )
    
    backup_mgr = create_backup_manager(config)
    backup = backup_mgr.create_backup()
    print(f"Created backup: {backup.backup_id}, size: {backup.size_bytes} bytes")
    
    backups = backup_mgr.list_backups()
    print(f"Total backups: {len(backups)}")