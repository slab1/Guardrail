"""Horizontal scaling, load balancing, and multi-tenancy for production deployment."""
import time
import uuid
import hashlib
import threading
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from guardrail.monitoring import get_metrics, MetricsRegistry
from guardrail.authzen import get_spiffe_provider, SPIFFEIdentityProvider


class ScalingStrategy(Enum):
    """Scaling strategies."""
    HORIZONTAL = "horizontal"
    VERTICAL = "vertical"
    HYBRID = "hybrid"


class LoadBalancingAlgorithm(Enum):
    """Load balancing algorithms."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_LATENCY = "least_latency"
    CONSISTENT_HASH = "consistent_hash"


@dataclass
class ServiceInstance:
    """A service instance in the cluster."""
    instance_id: str
    host: str
    port: int
    health: str = "healthy"
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: int = field(default_factory=lambda: int(time.time()))
    last_heartbeat: int = field(default_factory=lambda: int(time.time()))
    capacity: int = 100
    current_load: int = 0
    version: str = "1.0.0"
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Tenant:
    """Multi-tenant configuration."""
    tenant_id: str
    name: str
    created_at: int = field(default_factory=lambda: int(time.time()))
    plan: str = "standard"  # free, standard, enterprise
    limits: Dict[str, int] = field(default_factory=lambda: {
        "max_agents": 10,
        "max_plans_per_hour": 100,
        "max_concurrent_executions": 5,
        "max_storage_gb": 1,
        "max_audit_retention_days": 30,
    })
    features: Set[str] = field(default_factory=set)
    isolation_level: str = "shared"  # shared, dedicated, isolated
    custom_policies: Dict[str, Any] = field(default_factory=dict)
    contacts: List[str] = field(default_factory=list)
    billing_email: str = ""


class ServiceRegistry:
    """Service registry for horizontal scaling."""
    
    def __init__(self):
        self.instances: Dict[str, ServiceInstance] = {}
        self.lock = threading.RLock()
        self.instance_groups: Dict[str, Set[str]] = defaultdict(set)  # group -> instance_ids
    
    def register(self, instance: ServiceInstance) -> bool:
        """Register a service instance."""
        with self.lock:
            if instance.instance_id in self.instances:
                return False
            self.instances[instance.instance_id] = instance
            self.instance_groups[instance.tags.get("group", "default")].add(instance.instance_id)
            return True
    
    def unregister(self, instance_id: str) -> bool:
        """Unregister a service instance."""
        with self.lock:
            if instance_id not in self.instances:
                return False
            instance = self.instances[instance_id]
            group = instance.tags.get("group", "default")
            self.instance_groups[group].discard(instance_id)
            del self.instances[instance_id]
            return True
    
    def heartbeat(self, instance_id: str, health: str = "healthy", current_load: int = None) -> bool:
        """Update instance heartbeat."""
        with self.lock:
            if instance_id not in self.instances:
                return False
            self.instances[instance_id].last_heartbeat = int(time.time())
            self.instances[instance_id].health = health
            if current_load is not None:
                self.instances[instance_id].current_load = current_load
            return True
    
    def get_healthy_instances(self, group: str = "default", tags: Dict[str, str] = None) -> List[ServiceInstance]:
        """Get healthy instances matching criteria."""
        with self.lock:
            candidate_ids = self.instance_groups.get(group, set())
            instances = []
            for iid in candidate_ids:
                inst = self.instances.get(iid)
                if inst and inst.health == "healthy":
                    if tags:
                        if all(inst.tags.get(k) == v for k, v in tags.items()):
                            instances.append(inst)
                    else:
                        instances.append(inst)
            return instances
    
    def get_instance(self, instance_id: str) -> Optional[ServiceInstance]:
        """Get instance by ID."""
        with self.lock:
            return self.instances.get(instance_id)
    
    def list_instances(self, group: str = None) -> List[ServiceInstance]:
        """List all instances."""
        with self.lock:
            if group:
                candidate_ids = self.instance_groups.get(group, set())
                return [self.instances[iid] for iid in candidate_ids if iid in self.instances]
            return list(self.instances.values())
    
    def cleanup_stale_instances(self, max_age_seconds: int = 60):
        """Remove instances that haven't sent heartbeat."""
        with self.lock:
            now = int(time.time())
            stale = []
            for iid, inst in self.instances.items():
                if now - inst.last_heartbeat > max_age_seconds:
                    stale.append(iid)
            for iid in stale:
                self.unregister(iid)


class LoadBalancer:
    """Load balancer with multiple algorithms."""
    
    def __init__(self, registry: ServiceRegistry, algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.LEAST_LATENCY):
        self.registry = registry
        self.algorithm = algorithm
        self.round_robin_index = 0
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self.latency_history: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def select_instance(self, group: str = "default", tags: Dict[str, str] = None) -> Optional[ServiceInstance]:
        """Select an instance based on algorithm."""
        instances = self.registry.get_healthy_instances(group, tags)
        if not instances:
            return None
        
        with self.lock:
            if self.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
                idx = self.round_robin_index % len(instances)
                self.round_robin_index += 1
                return instances[idx]
            
            elif self.algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
                # Use connection count as primary key, instance_id as tiebreaker for deterministic distribution
                return min(instances, key=lambda i: (self.connection_counts.get(i.instance_id, 0), i.instance_id))
            
            elif self.algorithm == LoadBalancingAlgorithm.LEAST_LATENCY:
                def avg_latency(inst):
                    history = self.latency_history.get(inst.instance_id, [])
                    return sum(history) / len(history) if history else 0
                return min(instances, key=avg_latency)
            
            elif self.algorithm == LoadBalancingAlgorithm.CONSISTENT_HASH:
                # Simple consistent hash based on instance_id
                return min(instances, key=lambda i: i.instance_id)
            
            return instances[0]
    
    def record_connection(self, instance_id: str, delta: int = 1):
        """Record connection count change."""
        with self.lock:
            self.connection_counts[instance_id] += delta
    
    def record_latency(self, instance_id: str, latency: float):
        """Record latency for instance."""
        with self.lock:
            self.latency_history[instance_id].append(latency)
            # Keep only last 100 samples
            if len(self.latency_history[instance_id]) > 100:
                self.latency_history[instance_id] = self.latency_history[instance_id][-100:]


class AutoScaler:
    """Automatic scaling based on metrics."""
    
    def __init__(self, registry: ServiceRegistry, load_balancer: LoadBalancer):
        self.registry = registry
        self.load_balancer = load_balancer
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.check_interval = 30  # seconds
        self.scale_up_threshold = 0.8  # CPU/load
        self.scale_down_threshold = 0.3
        self.min_instances = 1
        self.max_instances = 10
        self.scale_up_cooldown = 300  # seconds
        self.scale_down_cooldown = 600
        self.last_scale_up = 0
        self.last_scale_down = 0
    
    def start(self):
        """Start auto-scaling loop."""
        self.running = True
        self.thread = threading.Thread(target=self._scale_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop auto-scaling loop."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _scale_loop(self):
        """Main scaling loop."""
        while self.running:
            try:
                self._evaluate_scaling()
            except Exception:
                pass
            time.sleep(self.check_interval)
    
    def _evaluate_scaling(self):
        """Evaluate whether to scale up or down."""
        now = time.time()
        instances = self.registry.list_instances()
        healthy = [i for i in instances if i.health == "healthy"]
        
        if not healthy:
            return
        
        # Calculate average load
        total_load = sum(i.current_load for i in healthy)
        total_capacity = sum(i.capacity for i in healthy)
        avg_load = total_load / total_capacity if total_capacity > 0 else 0
        
        # Scale up
        if avg_load > self.scale_up_threshold and len(healthy) < self.max_instances:
            if now - self.last_scale_up > self.scale_up_cooldown:
                self._scale_up()
                self.last_scale_up = now
        
        # Scale down
        elif avg_load < self.scale_down_threshold and len(healthy) > self.min_instances:
            if now - self.last_scale_down > self.scale_down_cooldown:
                self._scale_down()
                self.last_scale_down = now
    
    def _scale_up(self):
        """Trigger scale up (in practice would call orchestration API)."""
        # In production, this would call Kubernetes HPA, AWS ASG, etc.
        pass
    
    def _scale_down(self):
        """Trigger scale down."""
        pass


class TenantManager:
    """Multi-tenant management."""
    
    def __init__(self):
        self.tenants: Dict[str, Tenant] = {}
        self.tenant_instances: Dict[str, Set[str]] = defaultdict(set)  # tenant_id -> instance_ids
        self.lock = threading.RLock()
        self.spiffe_provider = get_spiffe_provider()
    
    def create_tenant(self, tenant: Tenant) -> bool:
        """Create a new tenant."""
        with self.lock:
            if tenant.tenant_id in self.tenants:
                return False
            self.tenants[tenant.tenant_id] = tenant
            return True
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID."""
        with self.lock:
            return self.tenants.get(tenant_id)
    
    def update_tenant(self, tenant_id: str, **updates) -> bool:
        """Update tenant configuration."""
        with self.lock:
            if tenant_id not in self.tenants:
                return False
            tenant = self.tenants[tenant_id]
            for key, value in updates.items():
                if hasattr(tenant, key):
                    setattr(tenant, key, value)
            return True
    
    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        with self.lock:
            if tenant_id not in self.tenants:
                return False
            # Clean up tenant instances
            for iid in self.tenant_instances.get(tenant_id, set()):
                pass  # Would unregister instances
            self.tenant_instances.pop(tenant_id, None)
            del self.tenants[tenant_id]
            return True
    
    def list_tenants(self) -> List[Tenant]:
        """List all tenants."""
        with self.lock:
            return list(self.tenants.values())
    
    def assign_instance(self, tenant_id: str, instance_id: str) -> bool:
        """Assign an instance to a tenant."""
        with self.lock:
            if tenant_id not in self.tenants:
                return False
            self.tenant_instances[tenant_id].add(instance_id)
            return True
    
    def get_tenant_instances(self, tenant_id: str) -> Set[str]:
        """Get instances assigned to a tenant."""
        with self.lock:
            return self.tenant_instances.get(tenant_id, set()).copy()
    
    def check_quota(self, tenant_id: str, resource: str, requested: int) -> bool:
        """Check if tenant has quota for resource."""
        with self.lock:
            tenant = self.tenants.get(tenant_id)
            if not tenant:
                return False
            limit = tenant.limits.get(resource, 0)
            # In production, would check current usage
            return requested <= limit
    
    def get_tenant_spiffe_id(self, tenant_id: str) -> str:
        """Get SPIFFE ID for tenant."""
        return f"spiffe://guardrail.example.com/tenant/{tenant_id}"


class ClusterManager:
    """High-level cluster management."""
    
    def __init__(self):
        self.registry = ServiceRegistry()
        self.load_balancer = LoadBalancer(self.registry)
        self.auto_scaler = AutoScaler(self.registry, self.load_balancer)
        self.tenant_manager = TenantManager()
        self.metrics = get_metrics()
    
    def start(self):
        """Start cluster services."""
        self.auto_scaler.start()
    
    def stop(self):
        """Stop cluster services."""
        self.auto_scaler.stop()
    
    def register_instance(self, instance: ServiceInstance) -> bool:
        """Register a service instance."""
        return self.registry.register(instance)
    
    def unregister_instance(self, instance_id: str) -> bool:
        """Unregister a service instance."""
        return self.registry.unregister(instance_id)
    
    def get_instance_for_request(
        self,
        group: str = "default",
        tags: Dict[str, str] = None
    ) -> Optional[ServiceInstance]:
        """Get instance for handling a request."""
        instance = self.load_balancer.select_instance(group, tags)
        if instance:
            self.load_balancer.record_connection(instance.instance_id, 1)
            instance.current_load += 1
        return instance
    
    def release_instance(self, instance_id: str, latency: float = None):
        """Release instance after request."""
        self.load_balancer.record_connection(instance_id, -1)
        inst = self.registry.get_instance(instance_id)
        if inst:
            inst.current_load = max(0, inst.current_load - 1)
        if latency is not None:
            self.load_balancer.record_latency(instance_id, latency)
    
    def create_tenant(self, tenant: Tenant) -> bool:
        """Create a tenant."""
        return self.tenant_manager.create_tenant(tenant)
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant."""
        return self.tenant_manager.get_tenant(tenant_id)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get cluster health status."""
        instances = self.registry.list_instances()
        healthy = [i for i in instances if i.health == "healthy"]
        total_capacity = sum(i.capacity for i in healthy)
        total_load = sum(i.current_load for i in healthy)
        
        return {
            "total_instances": len(instances),
            "healthy_instances": len(healthy),
            "total_capacity": total_capacity,
            "total_load": total_load,
            "avg_load": total_load / total_capacity if total_capacity > 0 else 0,
            "tenants": len(self.tenant_manager.tenants),
        }


# Global cluster manager
_cluster_manager: Optional[ClusterManager] = None


def get_cluster_manager() -> ClusterManager:
    """Get global cluster manager."""
    global _cluster_manager
    if _cluster_manager is None:
        _cluster_manager = ClusterManager()
    return _cluster_manager


def init_cluster(
    algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.LEAST_LATENCY,
    min_instances: int = 1,
    max_instances: int = 10,
):
    """Initialize cluster."""
    global _cluster_manager
    manager = ClusterManager()
    manager.load_balancer.algorithm = algorithm
    manager.auto_scaler.min_instances = min_instances
    manager.auto_scaler.max_instances = max_instances
    _cluster_manager = manager
    manager.start()
    return manager


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Initialize cluster
    cluster = init_cluster()
    
    # Register instances
    for i in range(3):
        inst = ServiceInstance(
            instance_id=f"guardrail-worker-{i}",
            host="localhost",
            port=8080 + i,
            capacity=100,
            tags={"group": "default", "zone": f"zone-{i % 2}"}
        )
        cluster.register_instance(inst)
    
    # Create tenant
    tenant = Tenant(
        tenant_id="tenant_acme",
        name="Acme Corp",
        plan="enterprise",
        limits={"max_agents": 100, "max_plans_per_hour": 1000},
        features={"advanced_audit", "custom_policies", "dedicated_instances"},
    )
    cluster.create_tenant(tenant)
    
    # Simulate requests
    for i in range(10):
        inst = cluster.get_instance_for_request()
        if inst:
            print(f"Request {i} -> {inst.instance_id}")
            time.sleep(0.1)
            cluster.release_instance(inst.instance_id, latency=0.05)
    
    # Health status
    health = cluster.get_health_status()
    print(f"\nCluster Health: {health}")
    
    # Stop
    cluster.stop()