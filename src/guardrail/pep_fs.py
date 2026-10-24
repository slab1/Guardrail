"""PEP-FS: Policy Enforcement Point for File System (LSFS - Semantic File System)."""
import os
import shutil
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from guardrail.pep_framework import BasePEP, PEPRequest, PEPResponse, PEPType, register_pep


@dataclass
class FileVersion:
    """Represents a version of a file."""
    path: str
    content: bytes
    timestamp: int
    version_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileSnapshot:
    """Snapshot of file system state for rollback."""
    snapshot_id: str
    timestamp: int
    files: Dict[str, FileVersion]  # path -> version
    metadata: Dict[str, Any] = field(default_factory=dict)


class LSFSStore:
    """LSFS (Logical Semantic File System) Store with versioning and rollback."""
    
    def __init__(self, root_path: str = "/tmp/guardrail_lsfs"):
        self.root_path = Path(root_path)
        self.root_path.mkdir(parents=True, exist_ok=True)
        self.versions: Dict[str, List[FileVersion]] = {}  # path -> list of versions
        self.snapshots: Dict[str, FileSnapshot] = {}
        self.current_snapshot_id: Optional[str] = None
    
    def _get_version_path(self, path: str, version_id: str) -> Path:
        """Get the storage path for a specific version."""
        safe_path = path.lstrip("/").replace("/", "_")
        version_dir = self.root_path / "versions" / safe_path
        version_dir.mkdir(parents=True, exist_ok=True)
        return version_dir / f"{version_id}.dat"
    
    def _compute_hash(self, content: bytes) -> str:
        """Compute SHA256 hash of content."""
        return hashlib.sha256(content).hexdigest()[:16]
    
    def read_file(self, path: str) -> PEPResponse:
        """Read a file."""
        full_path = self.root_path / "current" / path.lstrip("/")
        if not full_path.exists():
            return PEPResponse(
                success=False,
                error=f"File not found: {path}"
            )
        
        content = full_path.read_bytes()
        return PEPResponse(
            success=True,
            result={"content": content, "path": path},
            details={"size": len(content)}
        )
    
    def write_file(self, path: str, content: bytes, create_snapshot: bool = True) -> PEPResponse:
        """Write a file with versioning."""
        full_path = self.root_path / "current" / path.lstrip("/")
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Read current content for versioning
        old_content = b""
        if full_path.exists():
            old_content = full_path.read_bytes()
        
        # Create version record
        version_id = self._compute_hash(content + str(time.time()).encode())
        version = FileVersion(
            path=path,
            content=content,
            timestamp=int(time.time()),
            version_id=version_id,
            metadata={"previous_hash": self._compute_hash(old_content) if old_content else None}
        )
        
        # Store version
        version_path = self._get_version_path(path, version_id)
        version_path.write_bytes(content)
        
        if path not in self.versions:
            self.versions[path] = []
        self.versions[path].append(version)
        
        # Write current version
        full_path.write_bytes(content)
        
        # Create snapshot if requested
        snapshot_id = None
        if create_snapshot:
            snapshot_id = self.create_snapshot(f"write_{path}")
        
        rollback_info = {
            "path": path,
            "version_id": version_id,
            "previous_version": self.versions[path][-2].version_id if len(self.versions[path]) > 1 else None,
            "snapshot_id": snapshot_id,
        }
        
        return PEPResponse(
            success=True,
            result={"path": path, "version_id": version_id, "size": len(content)},
            rollback_info=rollback_info
        )
    
    def delete_file(self, path: str) -> PEPResponse:
        """Delete a file (with versioning for rollback)."""
        full_path = self.root_path / "current" / path.lstrip("/")
        if not full_path.exists():
            return PEPResponse(
                success=False,
                error=f"File not found: {path}"
            )
        
        # Read content for versioning before deletion
        content = full_path.read_bytes()
        version_id = self._compute_hash(content + b"deleted" + str(time.time()).encode())
        
        version = FileVersion(
            path=path,
            content=content,
            timestamp=int(time.time()),
            version_id=version_id,
            metadata={"deleted": True}
        )
        
        if path not in self.versions:
            self.versions[path] = []
        self.versions[path].append(version)
        
        # Store version
        version_path = self._get_version_path(path, version_id)
        version_path.write_bytes(content)
        
        # Delete current file
        full_path.unlink()
        
        snapshot_id = self.create_snapshot(f"delete_{path}")
        
        rollback_info = {
            "path": path,
            "version_id": version_id,
            "previous_version": self.versions[path][-2].version_id if len(self.versions[path]) > 1 else None,
            "snapshot_id": snapshot_id,
            "deleted": True,
        }
        
        return PEPResponse(
            success=True,
            result={"path": path, "deleted": True, "version_id": version_id},
            rollback_info=rollback_info
        )
    
    def list_files(self, path: str = "/") -> PEPResponse:
        """List files in a directory."""
        full_path = self.root_path / "current" / path.lstrip("/")
        if not full_path.exists():
            return PEPResponse(
                success=False,
                error=f"Directory not found: {path}"
            )
        
        files = []
        for item in full_path.iterdir():
            rel_path = item.relative_to(self.root_path / "current")
            files.append({
                "name": item.name,
                "path": str(rel_path),
                "is_dir": item.is_dir(),
                "size": item.stat().st_size if item.is_file() else 0,
            })
        
        return PEPResponse(
            success=True,
            result={"path": path, "files": files}
        )
    
    def create_snapshot(self, label: str = "") -> str:
        """Create a snapshot of current file system state."""
        snapshot_id = f"snap_{int(time.time())}_{hashlib.sha256(label.encode()).hexdigest()[:8]}"
        
        files = {}
        for path, versions in self.versions.items():
            if versions:
                files[path] = versions[-1]  # Latest version
        
        snapshot = FileSnapshot(
            snapshot_id=snapshot_id,
            timestamp=int(time.time()),
            files=files,
            metadata={"label": label}
        )
        
        self.snapshots[snapshot_id] = snapshot
        self.current_snapshot_id = snapshot_id
        
        return snapshot_id
    
    def rollback_to_snapshot(self, snapshot_id: str) -> PEPResponse:
        """Rollback file system to a snapshot."""
        if snapshot_id not in self.snapshots:
            return PEPResponse(
                success=False,
                error=f"Snapshot not found: {snapshot_id}"
            )
        
        snapshot = self.snapshots[snapshot_id]
        
        # Clear current directory
        current_dir = self.root_path / "current"
        if current_dir.exists():
            shutil.rmtree(current_dir)
        current_dir.mkdir(parents=True, exist_ok=True)
        
        # Restore files
        restored = []
        for path, version in snapshot.files.items():
            if version.metadata.get("deleted"):
                continue  # Skip deleted files
            
            full_path = current_dir / path.lstrip("/")
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(version.content)
            restored.append(path)
        
        return PEPResponse(
            success=True,
            result={"snapshot_id": snapshot_id, "restored_files": restored}
        )
    
    def rollback_file(self, path: str, version_id: Optional[str] = None) -> PEPResponse:
        """Rollback a specific file to a previous version."""
        if path not in self.versions or not self.versions[path]:
            return PEPResponse(
                success=False,
                error=f"No versions found for file: {path}"
            )
        
        versions = self.versions[path]
        target_version = None
        
        if version_id:
            for v in versions:
                if v.version_id == version_id:
                    target_version = v
                    break
        else:
            # Rollback to previous version
            if len(versions) > 1:
                target_version = versions[-2]
        
        if not target_version:
            return PEPResponse(
                success=False,
                error=f"Version not found: {version_id}"
            )
        
        # Restore file
        full_path = self.root_path / "current" / path.lstrip("/")
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(target_version.content)
        
        # Create new version for the rollback
        new_version_id = self._compute_hash(target_version.content + b"rollback" + str(time.time()).encode())
        new_version = FileVersion(
            path=path,
            content=target_version.content,
            timestamp=int(time.time()),
            version_id=new_version_id,
            metadata={"rolled_back_from": target_version.version_id}
        )
        versions.append(new_version)
        
        return PEPResponse(
            success=True,
            result={"path": path, "rolled_back_to": target_version.version_id, "new_version": new_version_id}
        )
    
    def get_file_history(self, path: str) -> List[FileVersion]:
        """Get version history for a file."""
        return self.versions.get(path, [])
    
    def list_snapshots(self) -> List[FileSnapshot]:
        """List all snapshots."""
        return list(self.snapshots.values())


class PepFs(BasePEP):
    """PEP-FS: Policy Enforcement Point for File System operations."""
    
    def __init__(self, store: Optional[LSFSStore] = None):
        super().__init__(PEPType.FS)
        self.store = store or LSFSStore()
        
        # Define allowed actions
        self.allowed_actions = {
            "file_read", "file_write", "file_delete", "file_list",
            "file_rollback", "file_snapshot", "file_history",
        }
        self.action_categories = {
            "file_read": "read",
            "file_write": "write",
            "file_delete": "write",
            "file_list": "read",
            "file_rollback": "write",
            "file_snapshot": "write",
            "file_history": "read",
        }
    
    def enforce(self, request: PEPRequest) -> PEPResponse:
        """Enforce file system policy."""
        # Validate token
        if not self.validate_token(request):
            return self.create_denied_response(request, "Invalid or expired token")
        
        # Check if action is allowed
        if not self.check_action_allowed(request.action):
            return self.create_denied_response(request, f"Action not allowed: {request.action}")
        
        # Route to appropriate handler
        try:
            if request.action == "file_read":
                return self.store.read_file(request.resource)
            elif request.action == "file_write":
                content = request.metadata.get("content", b"")
                if isinstance(content, str):
                    content = content.encode()
                return self.store.write_file(request.resource, content)
            elif request.action == "file_delete":
                return self.store.delete_file(request.resource)
            elif request.action == "file_list":
                return self.store.list_files(request.resource)
            elif request.action == "file_rollback":
                version_id = request.metadata.get("version_id")
                return self.store.rollback_file(request.resource, version_id)
            elif request.action == "file_snapshot":
                label = request.metadata.get("label", "")
                snap_id = self.store.create_snapshot(label)
                return PEPResponse(
                    success=True,
                    result={"snapshot_id": snap_id}
                )
            elif request.action == "file_history":
                history = self.store.get_file_history(request.resource)
                return PEPResponse(
                    success=True,
                    result={"path": request.resource, "versions": [
                        {"version_id": v.version_id, "timestamp": v.timestamp, "metadata": v.metadata}
                        for v in history
                    ]}
                )
            else:
                return self.create_denied_response(request, f"Unknown action: {request.action}")
        except Exception as e:
            return self.create_denied_response(request, f"Execution error: {str(e)}")


# Convenience function to create and register pep-fs
def create_pep_fs(root_path: str = "/tmp/guardrail_lsfs") -> PepFs:
    """Create and register a PepFs instance."""
    store = LSFSStore(root_path)
    pep_fs = PepFs(store)
    register_pep(pep_fs)
    return pep_fs


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    pep_fs = create_pep_fs()
    
    # Test write
    from guardrail.token_service import create_step_token
    token = create_step_token("plan_001", "step_001", "Write config", "coding", "user1", 1)
    
    request = PEPRequest(
        pep_type=PEPType.FS,
        token=token,
        plan_id="plan_001",
        step_id="step_001",
        agent_class="coding",
        user_id="user1",
        autonomy_level=1,
        action="file_write",
        resource="/etc/config.yaml",
        metadata={"content": "key: value\n"}
    )
    
    response = pep_fs.enforce(request)
    print(f"Write: {response.success}, {response.result}")
    
    # Test read
    request.action = "file_read"
    request.metadata = {}
    response = pep_fs.enforce(request)
    print(f"Read: {response.success}, {response.result}")
    
    # Test snapshot
    request.action = "file_snapshot"
    request.resource = "/"
    response = pep_fs.enforce(request)
    print(f"Snapshot: {response.success}, {response.result}")
    
    # Test rollback
    if response.success:
        snap_id = response.result["snapshot_id"]
        request.action = "file_rollback"
        request.resource = "/etc/config.yaml"
        request.metadata = {"version_id": None}  # Rollback to previous
        response = pep_fs.enforce(request)
        print(f"Rollback: {response.success}, {response.result}")