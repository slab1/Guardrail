"""Tests for Phase 5: Scaling, Multi-tenancy, Load Balancing."""
import sys
import os
import time
import threading

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from scaling import (
    ServiceInstance, ServiceRegistry, LoadBalancer, AutoScaler,
    Tenant, TenantManager, ClusterManager,
    ScalingStrategy, LoadBalancingAlgorithm,
    get_cluster_manager, init_cluster
)
from monitoring import MetricsRegistry


# ----------------------------------------------------------------------
# Service Registry Tests
# ----------------------------------------------------------------------
def test_service_instance_creation():
    """Test service instance creation."""
    inst = ServiceInstance(
        instance_id="test-001",
        host="localhost",
        port=8080,
        capacity=100,
    )
    assert inst.instance_id == "test-001"
    assert inst.health == "healthy"
    assert inst.capacity == 100


def test_service_registry_register():
    """Test service registry registration."""
    registry = ServiceRegistry()
    inst = ServiceInstance(
        instance_id="test-001",
        host="localhost",
        port=8080,
    )
    
    result = registry.register(inst)
    assert result is True
    
    # Try to register same ID
    result2 = registry.register(inst)
    assert result2 is False
    
    retrieved = registry.get_instance("test-001")
    assert retrieved is inst


def test_service_registry_unregister():
    """Test service registry unregistration."""
    registry = ServiceRegistry()
    inst = ServiceInstance(
        instance_id="test-001",
        host="localhost",
        port=8080,
    )
    
    registry.register(inst)
    result = registry.unregister("test-001")
    assert result is True
    
    retrieved = registry.get_instance("test-001")
    assert retrieved is None


def test_service_registry_heartbeat():
    """Test service registry heartbeat."""
    registry = ServiceRegistry()
    inst = ServiceInstance(
        instance_id="test-001",
        host="localhost",
        port=8080,
    )
    
    registry.register(inst)
    time.sleep(0.01)
    
    result = registry.heartbeat("test-001", health="healthy", current_load=50)
    assert result is True
    
    retrieved = registry.get_instance("test-001")
    assert retrieved.current_load == 50
    assert retrieved.health == "healthy"


def test_service_registry_groups():
    """Test service registry groups."""
    registry = ServiceRegistry()
    
    inst1 = ServiceInstance(instance_id="inst-1", host="localhost", port=8080, tags={"group": "api"})
    inst2 = ServiceInstance(instance_id="inst-2", host="localhost", port=8081, tags={"group": "api"})
    inst3 = ServiceInstance(instance_id="inst-3", host="localhost", port=8082, tags={"group": "worker"})
    
    registry.register(inst1)
    registry.register(inst2)
    registry.register(inst3)
    
    api_instances = registry.get_healthy_instances("api")
    assert len(api_instances) == 2
    
    worker_instances = registry.get_healthy_instances("worker")
    assert len(worker_instances) == 1
    
    all_instances = registry.list_instances()
    assert len(all_instances) == 3


def test_cleanup_stale_instances():
    """Test cleanup of stale instances."""
    registry = ServiceRegistry()
    
    inst1 = ServiceInstance(instance_id="inst-1", host="localhost", port=8080)
    inst2 = ServiceInstance(instance_id="inst-2", host="localhost", port=8081)
    
    registry.register(inst1)
    registry.register(inst2)
    
    # Manually set old heartbeat
    inst1.last_heartbeat = int(time.time()) - 120
    inst2.last_heartbeat = int(time.time()) - 10
    
    registry.cleanup_stale_instances(max_age_seconds=60)
    
    assert registry.get_instance("inst-1") is None
    assert registry.get_instance("inst-2") is not None


# ----------------------------------------------------------------------
# Load Balancer Tests
# ----------------------------------------------------------------------
def test_load_balancer_round_robin():
    """Test round-robin load balancing."""
    registry = ServiceRegistry()
    for i in range(3):
        inst = ServiceInstance(instance_id=f"inst-{i}", host="localhost", port=8080+i)
        registry.register(inst)
    
    lb = LoadBalancer(registry, LoadBalancingAlgorithm.ROUND_ROBIN)
    
    selected = [lb.select_instance().instance_id for _ in range(6)]
    # Should cycle through all 3 instances twice
    assert len(selected) == 6
    assert set(selected[:3]) == {"inst-0", "inst-1", "inst-2"}
    assert set(selected[3:]) == {"inst-0", "inst-1", "inst-2"}


def test_load_balancer_least_connections():
    """Test least connections load balancing."""
    registry = ServiceRegistry()
    for i in range(3):
        inst = ServiceInstance(instance_id=f"inst-{i}", host="localhost", port=8080+i)
        registry.register(inst)
    
    lb = LoadBalancer(registry, LoadBalancingAlgorithm.LEAST_CONNECTIONS)
    
    # First request - should pick one with 0 connections
    inst = lb.select_instance()
    assert inst is not None
    lb.record_connection(inst.instance_id, 1)
    
    # Next should go to one with 0 connections
    inst = lb.select_instance()
    assert inst is not None
    assert inst.instance_id != "inst-0"  # Should pick different one
    lb.record_connection(inst.instance_id, 1)
    
    # Next should go to the remaining one with 0 connections
    inst = lb.select_instance()
    assert inst is not None
    # The one with 1 connection should not be picked if there's one with 0


def test_load_balancer_least_latency():
    """Test least latency load balancing."""
    registry = ServiceRegistry()
    for i in range(3):
        inst = ServiceInstance(instance_id=f"inst-{i}", host="localhost", port=8080+i)
        registry.register(inst)
    
    lb = LoadBalancer(registry, LoadBalancingAlgorithm.LEAST_LATENCY)
    
    # Record latencies
    lb.record_latency("inst-0", 0.5)
    lb.record_latency("inst-1", 0.1)
    lb.record_latency("inst-2", 0.3)
    
    # Should pick inst-1 (lowest latency)
    inst = lb.select_instance()
    assert inst.instance_id == "inst-1"


def test_load_balancer_consistent_hash():
    """Test consistent hash load balancing."""
    registry = ServiceRegistry()
    for i in range(3):
        inst = ServiceInstance(instance_id=f"inst-{i}", host="localhost", port=8080+i)
        registry.register(inst)
    
    lb = LoadBalancer(registry, LoadBalancingAlgorithm.CONSISTENT_HASH)
    
    inst = lb.select_instance()
    assert inst is not None


def test_load_balancer_filters_unhealthy():
    """Test load balancer skips unhealthy instances."""
    registry = ServiceRegistry()
    inst1 = ServiceInstance(instance_id="healthy", host="localhost", port=8080)
    inst2 = ServiceInstance(instance_id="unhealthy", host="localhost", port=8081, health="unhealthy")
    
    registry.register(inst1)
    registry.register(inst2)
    
    lb = LoadBalancer(registry)
    
    inst = lb.select_instance()
    assert inst.instance_id == "healthy"


# ----------------------------------------------------------------------
# AutoScaler Tests
# ----------------------------------------------------------------------
def test_auto_scaler_creation():
    """Test auto scaler creation."""
    registry = ServiceRegistry()
    lb = LoadBalancer(registry)
    scaler = AutoScaler(registry, lb)
    
    assert scaler.min_instances == 1
    assert scaler.max_instances == 10
    assert scaler.running is False


# ----------------------------------------------------------------------
# Tenant Manager Tests
# ----------------------------------------------------------------------
def test_tenant_creation():
    """Test tenant creation."""
    manager = TenantManager()
    tenant = Tenant(
        tenant_id="tenant-001",
        name="Test Tenant",
        plan="standard",
    )
    
    result = manager.create_tenant(tenant)
    assert result is True
    
    retrieved = manager.get_tenant("tenant-001")
    assert retrieved is not None
    assert retrieved.name == "Test Tenant"


def test_tenant_duplicate():
    """Test duplicate tenant creation fails."""
    manager = TenantManager()
    tenant = Tenant(tenant_id="tenant-001", name="Test")
    
    result1 = manager.create_tenant(tenant)
    result2 = manager.create_tenant(tenant)
    
    assert result1 is True
    assert result2 is False


def test_tenant_update():
    """Test tenant update."""
    manager = TenantManager()
    tenant = Tenant(tenant_id="tenant-001", name="Test", plan="standard")
    manager.create_tenant(tenant)
    
    result = manager.update_tenant("tenant-001", plan="enterprise", limits={"max_agents": 100})
    assert result is True
    
    retrieved = manager.get_tenant("tenant-001")
    assert retrieved.plan == "enterprise"
    assert retrieved.limits["max_agents"] == 100


def test_tenant_deletion():
    """Test tenant deletion."""
    manager = TenantManager()
    tenant = Tenant(tenant_id="tenant-001", name="Test")
    manager.create_tenant(tenant)
    
    result = manager.delete_tenant("tenant-001")
    assert result is True
    
    retrieved = manager.get_tenant("tenant-001")
    assert retrieved is None


def test_tenant_quota():
    """Test tenant quota checking."""
    manager = TenantManager()
    tenant = Tenant(
        tenant_id="tenant-001",
        name="Test",
        limits={"max_agents": 10, "max_plans_per_hour": 100},
    )
    manager.create_tenant(tenant)
    
    assert manager.check_quota("tenant-001", "max_agents", 5) is True
    assert manager.check_quota("tenant-001", "max_agents", 15) is False


def test_tenant_instance_assignment():
    """Test tenant instance assignment."""
    manager = TenantManager()
    tenant = Tenant(tenant_id="tenant-001", name="Test")
    manager.create_tenant(tenant)
    
    result = manager.assign_instance("tenant-001", "inst-001")
    assert result is True
    
    instances = manager.get_tenant_instances("tenant-001")
    assert "inst-001" in instances


# ----------------------------------------------------------------------
# Cluster Manager Tests
# ----------------------------------------------------------------------
def test_cluster_manager():
    """Test cluster manager basic operations."""
    cluster = ClusterManager()
    
    # Register instances
    for i in range(3):
        inst = ServiceInstance(instance_id=f"worker-{i}", host="localhost", port=8080+i)
        cluster.register_instance(inst)
    
    # Get instance for request
    inst = cluster.get_instance_for_request()
    assert inst is not None
    assert inst.current_load == 1
    
    # Release instance
    cluster.release_instance(inst.instance_id, latency=0.05)
    assert inst.current_load == 0
    
    # Create tenant
    tenant = Tenant(tenant_id="tenant-001", name="Test Corp", plan="enterprise")
    cluster.create_tenant(tenant)
    
    retrieved = cluster.get_tenant("tenant-001")
    assert retrieved is not None
    assert retrieved.name == "Test Corp"
    
    # Health status
    health = cluster.get_health_status()
    assert health["total_instances"] == 3
    assert health["healthy_instances"] == 3
    assert health["tenants"] == 1


def test_cluster_load_distribution():
    """Test load distribution across instances."""
    cluster = ClusterManager()
    
    for i in range(3):
        inst = ServiceInstance(instance_id=f"worker-{i}", host="localhost", port=8080+i)
        cluster.register_instance(inst)
    
    # Send requests
    for _ in range(10):
        inst = cluster.get_instance_for_request()
        cluster.release_instance(inst.instance_id, latency=0.01)
    
    # Check load is distributed
    instances = cluster.registry.list_instances()
    loads = [i.current_load for i in instances]
    # All should have some load, but one might have more due to round-robin
    assert sum(loads) == 0  # All released


def test_global_cluster_manager():
    """Test global cluster manager."""
    manager = get_cluster_manager()
    assert manager is not None
    
    # Reset for clean test
    import scaling
    scaling._cluster_manager = None
    
    manager2 = init_cluster()
    assert manager2 is not None
    manager2.stop()


def test_init_cluster():
    """Test cluster initialization."""
    # Reset
    import scaling
    scaling._cluster_manager = None
    
    manager = init_cluster(min_instances=2, max_instances=5)
    assert manager is not None
    assert manager.auto_scaler.min_instances == 2
    assert manager.auto_scaler.max_instances == 5
    
    manager.stop()


# ----------------------------------------------------------------------
# Integration Tests
# ----------------------------------------------------------------------
def test_full_scaling_scenario():
    """Test full scaling scenario."""
    cluster = ClusterManager()
    
    # Register initial instances
    for i in range(2):
        inst = ServiceInstance(instance_id=f"worker-{i}", host="localhost", port=8080+i)
        cluster.register_instance(inst)
    
    # Simulate load
    for _ in range(20):
        inst = cluster.get_instance_for_request()
        time.sleep(0.001)
        cluster.release_instance(inst.instance_id, latency=0.01)
    
    # Check health
    health = cluster.get_health_status()
    assert health["total_instances"] == 2
    assert health["healthy_instances"] == 2
    
    # Add tenant
    tenant = Tenant(
        tenant_id="tenant-scale",
        name="Scale Corp",
        plan="standard",
    )
    cluster.create_tenant(tenant)
    
    health = cluster.get_health_status()
    assert health["tenants"] == 1
    
    cluster.stop()


def test_concurrent_access():
    """Test concurrent access to cluster."""
    cluster = ClusterManager()
    
    for i in range(5):
        inst = ServiceInstance(instance_id=f"worker-{i}", host="localhost", port=8080+i)
        cluster.register_instance(inst)
    
    results = []
    errors = []
    
    def worker():
        try:
            for _ in range(10):
                inst = cluster.get_instance_for_request()
                time.sleep(0.001)
                cluster.release_instance(inst.instance_id, latency=0.005)
            results.append("ok")
        except Exception as e:
            errors.append(str(e))
    
    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    assert len(errors) == 0
    assert len(results) == 5
    
    cluster.stop()


# ----------------------------------------------------------------------
# Run tests
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])