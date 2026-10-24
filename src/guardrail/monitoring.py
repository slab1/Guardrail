"""Production monitoring and metrics (Prometheus/OpenTelemetry)."""
import time
import threading
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from contextlib import contextmanager
import sys

# Optional imports for production
try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    Counter = Histogram = Gauge = CollectorRegistry = generate_latest = None

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    trace = TracerProvider = BatchSpanProcessor = OTLPSpanExporter = RequestsInstrumentor = None


@dataclass
class MetricLabels:
    """Standard labels for all metrics."""
    agent_id: str = "unknown"
    agent_class: str = "unknown"
    plan_id: str = "unknown"
    step_id: str = "unknown"
    autonomy_level: str = "0"
    trust_level: str = "LOCKED"


class MockCounter:
    """Mock counter when Prometheus not available."""
    def __init__(self, name: str, documentation: str, labelnames: List[str], registry=None):
        self.name = name
        self.value = 0
        self.labels_dict: Dict[tuple, int] = defaultdict(int)
        self.lock = threading.Lock()
    
    def labels(self, **kwargs) -> "MockCounter":
        label_key = tuple(sorted(kwargs.items()))
        return MockLabeledCounter(self, label_key)
    
    def inc(self, amount: float = 1.0):
        with self.lock:
            self.value += amount


class MockLabeledCounter:
    """Mock labeled counter."""
    def __init__(self, parent: MockCounter, label_key: tuple):
        self.parent = parent
        self.label_key = label_key
    
    def inc(self, amount: float = 1.0):
        with self.parent.lock:
            self.parent.labels_dict[self.label_key] += amount
            self.parent.value += amount


class MockHistogram:
    """Mock histogram when Prometheus not available."""
    def __init__(self, name: str, documentation: str, labelnames: List[str], buckets: List[float] = None, registry=None):
        self.name = name
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.observations: List[float] = []
        self.lock = threading.Lock()
    
    def labels(self, **kwargs) -> "MockHistogram":
        return self
    
    def observe(self, value: float):
        with self.lock:
            self.observations.append(value)
    
    def time(self) -> "MockTimer":
        return MockTimer(self)


class MockTimer:
    """Context manager for timing."""
    def __init__(self, histogram: MockHistogram):
        self.histogram = histogram
        self.start = 0.0
    
    def __enter__(self):
        self.start = time.time()
        return self
    
    def __exit__(self, *args):
        self.histogram.observe(time.time() - self.start)


class MockGauge:
    """Mock gauge when Prometheus not available."""
    def __init__(self, name: str, documentation: str, labelnames: List[str], registry=None):
        self.name = name
        self.value = 0.0
        self.labels_dict: Dict[tuple, float] = defaultdict(float)
        self.lock = threading.Lock()
    
    def labels(self, **kwargs) -> "MockGauge":
        label_key = tuple(sorted(kwargs.items()))
        return MockLabeledGauge(self, label_key)
    
    def set(self, value: float):
        with self.lock:
            self.value = value
    
    def inc(self, amount: float = 1.0):
        with self.lock:
            self.value += amount
    
    def dec(self, amount: float = 1.0):
        with self.lock:
            self.value -= amount


class MockLabeledGauge:
    """Mock labeled gauge."""
    def __init__(self, parent: MockGauge, label_key: tuple):
        self.parent = parent
        self.label_key = label_key
    
    def set(self, value: float):
        with self.parent.lock:
            self.parent.labels_dict[self.label_key] = value
            self.parent.value = value
    
    def inc(self, amount: float = 1.0):
        with self.parent.lock:
            self.parent.labels_dict[self.label_key] += amount
            self.parent.value += amount
    
    def dec(self, amount: float = 1.0):
        with self.parent.lock:
            self.parent.labels_dict[self.label_key] -= amount
            self.parent.value -= amount


class MetricsRegistry:
    """Central metrics registry for Guardrail."""
    
    def __init__(self, use_prometheus: bool = True):
        self.use_prometheus = use_prometheus and PROMETHEUS_AVAILABLE
        self.registry = CollectorRegistry() if self.use_prometheus else None
        self.lock = threading.Lock()
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize all metrics."""
        if self.use_prometheus:
            CounterClass = Counter
            HistogramClass = Histogram
            GaugeClass = Gauge
            registry_arg = {"registry": self.registry}
        else:
            CounterClass = MockCounter
            HistogramClass = MockHistogram
            GaugeClass = MockGauge
            registry_arg = {}
        
        # Common label names
        common_labels = ["agent_id", "agent_class", "plan_id", "step_id", "autonomy_level", "trust_level"]
        auth_labels = ["agent_id", "agent_class", "decision"]
        pep_labels = ["pep_type", "action", "result"]
        
        # Request/Decision metrics
        self.authz_requests_total = CounterClass(
            "guardrail_authz_requests_total",
            "Total authorization requests",
            common_labels + ["decision"],
            **registry_arg
        )
        
        self.authz_latency_seconds = HistogramClass(
            "guardrail_authz_latency_seconds",
            "Authorization decision latency",
            common_labels,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry=self.registry
        )
        
        # Plan execution metrics
        self.plans_created_total = CounterClass(
            "guardrail_plans_created_total",
            "Total plans created",
            common_labels,
            registry=self.registry
        )
        
        self.plans_executed_total = CounterClass(
            "guardrail_plans_executed_total",
            "Total plans executed to completion",
            common_labels,
            registry=self.registry
        )
        
        self.plan_execution_duration_seconds = HistogramClass(
            "guardrail_plan_execution_duration_seconds",
            "Plan execution duration",
            common_labels,
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0],
            registry=self.registry
        )
        
        self.steps_executed_total = CounterClass(
            "guardrail_steps_executed_total",
            "Total steps executed",
            common_labels + ["action", "result"],
            registry=self.registry
        )
        
        self.step_latency_seconds = HistogramClass(
            "guardrail_step_latency_seconds",
            "Step execution latency",
            common_labels + ["action"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry=self.registry
        )
        
        # Consent metrics
        self.consent_requests_total = CounterClass(
            "guardrail_consent_requests_total",
            "Total consent requests",
            common_labels + ["risk_level", "result"],
            registry=self.registry
        )
        
        self.consent_latency_seconds = HistogramClass(
            "guardrail_consent_latency_seconds",
            "Consent decision latency",
            common_labels + ["risk_level"],
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 60.0, 300.0],
            registry=self.registry
        )
        
        # Token metrics
        self.tokens_created_total = CounterClass(
            "guardrail_tokens_created_total",
            "Total tokens created",
            common_labels + ["token_type"],
            registry=self.registry
        )
        
        self.token_validations_total = CounterClass(
            "guardrail_token_validations_total",
            "Total token validations",
            common_labels + ["valid"],
            registry=self.registry
        )
        
        # PEP enforcement metrics
        self.pep_enforcements_total = CounterClass(
            "guardrail_pep_enforcements_total",
            "Total PEP enforcements",
            pep_labels,
            registry=self.registry
        )
        
        self.pep_latency_seconds = HistogramClass(
            "guardrail_pep_latency_seconds",
            "PEP enforcement latency",
            pep_labels,
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry=self.registry
        )
        
        # Audit metrics
        self.audit_events_total = CounterClass(
            "guardrail_audit_events_total",
            "Total audit events logged",
            ["event_type", "agent_id"],
            registry=self.registry
        )
        
        self.audit_integrity_checks_total = CounterClass(
            "guardrail_audit_integrity_checks_total",
            "Total audit integrity checks",
            ["result"],
            registry=self.registry
        )
        
        # Trust/Autopilot metrics
        self.trust_score = GaugeClass(
            "guardrail_trust_score",
            "Current trust score",
            ["agent_id", "agent_class"],
            registry=self.registry
        )
        
        self.trust_level = GaugeClass(
            "guardrail_trust_level",
            "Current trust level (0=LOCKED, 1=PROTECTED, 2=UNRESTRICTED, 3=AUTONOMOUS)",
            ["agent_id", "agent_class"],
            registry=self.registry
        )
        
        self.effective_autonomy = GaugeClass(
            "guardrail_effective_autonomy",
            "Effective autonomy level",
            ["agent_id", "agent_class"],
            registry=self.registry
        )
        
        self.violations_total = CounterClass(
            "guardrail_violations_total",
            "Total policy violations",
            common_labels + ["violation_type"],
            registry=self.registry
        )
        
        # System metrics
        self.active_agents = GaugeClass(
            "guardrail_active_agents",
            "Number of active agents",
            [],
            registry=self.registry
        )
        
        self.active_plans = GaugeClass(
            "guardrail_active_plans",
            "Number of active plans",
            [],
            registry=self.registry
        )
        
        self.system_errors_total = CounterClass(
            "guardrail_system_errors_total",
            "Total system errors",
            ["component", "error_type"],
            registry=self.registry
        )
    
    def get_prometheus_metrics(self) -> bytes:
        """Get Prometheus metrics output."""
        if self.use_prometheus:
            return generate_latest(self.registry)
        return b"# Prometheus not available\n"
    
    def record_authz_request(self, labels: MetricLabels, decision: str, latency: float):
        """Record an authorization request."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "decision": decision,
        }
        self.authz_requests_total.labels(**label_dict).inc()
        latency_labels = {k: v for k, v in label_dict.items() if k != "decision"}
        self.authz_latency_seconds.labels(**latency_labels).observe(latency)
    
    def record_plan_created(self, labels: MetricLabels):
        """Record a plan creation."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
        }
        self.plans_created_total.labels(**label_dict).inc()
        self.active_plans.inc()
    
    def record_plan_executed(self, labels: MetricLabels, duration: float):
        """Record a plan completion."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
        }
        self.plans_executed_total.labels(**label_dict).inc()
        self.plan_execution_duration_seconds.labels(**label_dict).observe(duration)
        self.active_plans.dec()
    
    def record_step(self, labels: MetricLabels, action: str, result: str, latency: float):
        """Record a step execution."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "action": action,
            "result": result,
        }
        self.steps_executed_total.labels(**label_dict).inc()
        latency_labels = {k: v for k, v in label_dict.items() if k not in ["action", "result"]}
        self.step_latency_seconds.labels(**latency_labels).observe(latency)
    
    def record_consent(self, labels: MetricLabels, risk_level: str, result: str, latency: float):
        """Record a consent decision."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "risk_level": risk_level,
            "result": result,
        }
        self.consent_requests_total.labels(**label_dict).inc()
        latency_labels = {k: v for k, v in label_dict.items() if k != "result"}
        self.consent_latency_seconds.labels(**latency_labels).observe(latency)
    
    def record_token_created(self, labels: MetricLabels, token_type: str):
        """Record token creation."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "token_type": token_type,
        }
        self.tokens_created_total.labels(**label_dict).inc()
    
    def record_token_validation(self, labels: MetricLabels, valid: bool):
        """Record token validation."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "valid": str(valid).lower(),
        }
        self.token_validations_total.labels(**label_dict).inc()
    
    def record_pep_enforcement(self, pep_type: str, action: str, result: str, latency: float):
        """Record PEP enforcement."""
        label_dict = {
            "pep_type": pep_type,
            "action": action,
            "result": result,
        }
        self.pep_enforcements_total.labels(**label_dict).inc()
        self.pep_latency_seconds.labels(**label_dict).observe(latency)
    
    def record_audit_event(self, event_type: str, agent_id: str):
        """Record audit event."""
        self.audit_events_total.labels(event_type=event_type, agent_id=agent_id).inc()
    
    def record_audit_integrity_check(self, result: str):
        """Record audit integrity check."""
        self.audit_integrity_checks_total.labels(result=result).inc()
    
    def update_trust_score(self, agent_id: str, agent_class: str, score: float):
        """Update trust score gauge."""
        self.trust_score.labels(agent_id=agent_id, agent_class=agent_class).set(score)
    
    def update_trust_level(self, agent_id: str, agent_class: str, level: int):
        """Update trust level gauge."""
        self.trust_level.labels(agent_id=agent_id, agent_class=agent_class).set(level)
    
    def update_effective_autonomy(self, agent_id: str, agent_class: str, level: int):
        """Update effective autonomy gauge."""
        self.effective_autonomy.labels(agent_id=agent_id, agent_class=agent_class).set(level)
    
    def record_violation(self, labels: MetricLabels, violation_type: str):
        """Record a policy violation."""
        label_dict = {
            "agent_id": labels.agent_id,
            "agent_class": labels.agent_class,
            "plan_id": labels.plan_id,
            "step_id": labels.step_id,
            "autonomy_level": labels.autonomy_level,
            "trust_level": labels.trust_level,
            "violation_type": violation_type,
        }
        self.violations_total.labels(**label_dict).inc()
    
    def set_active_agents(self, count: int):
        """Set active agents count."""
        self.active_agents.set(count)
    
    def record_error(self, component: str, error_type: str):
        """Record a system error."""
        self.system_errors_total.labels(component=component, error_type=error_type).inc()


class OpenTelemetryTracer:
    """OpenTelemetry distributed tracing setup."""
    
    def __init__(self, service_name: str = "guardrail", otlp_endpoint: str = "localhost:4317"):
        self.service_name = service_name
        self.otlp_endpoint = otlp_endpoint
        self.tracer = None
        self.provider = None
        self._init_tracing()
    
    def _init_tracing(self):
        """Initialize OpenTelemetry tracing."""
        if not OPENTELEMETRY_AVAILABLE:
            return
        
        self.provider = TracerProvider()
        processor = BatchSpanProcessor(
            OTLPSpanExporter(endpoint=self.otlp_endpoint, insecure=True)
        )
        self.provider.add_span_processor(processor)
        trace.set_tracer_provider(self.provider)
        self.tracer = trace.get_tracer(self.service_name)
        
        # Auto-instrument requests
        RequestsInstrumentor().instrument()
    
    def start_span(self, name: str, attributes: Dict[str, Any] = None):
        """Start a new span."""
        if not self.tracer:
            return MockSpan()
        return self.tracer.start_as_current_span(name, attributes=attributes or {})
    
    @contextmanager
    def trace_operation(self, name: str, attributes: Dict[str, Any] = None):
        """Context manager for tracing an operation."""
        if not self.tracer:
            yield MockSpan()
            return
        
        with self.tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            yield span


class MockSpan:
    """Mock span when OpenTelemetry not available."""
    def __init__(self):
        self.attributes = {}
    
    def set_attribute(self, key: str, value: Any):
        self.attributes[key] = value
    
    def add_event(self, name: str, attributes: Dict[str, Any] = None):
        pass
    
    def end(self):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass


# Global instances
_metrics: Optional[MetricsRegistry] = None
_tracer: Optional[OpenTelemetryTracer] = None


def get_metrics() -> MetricsRegistry:
    """Get global metrics registry."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsRegistry()
    return _metrics


def get_tracer() -> OpenTelemetryTracer:
    """Get global tracer."""
    global _tracer
    if _tracer is None:
        _tracer = OpenTelemetryTracer()
    return _tracer


def init_monitoring(use_prometheus: bool = True, otlp_endpoint: str = "localhost:4317"):
    """Initialize monitoring."""
    global _metrics, _tracer
    _metrics = MetricsRegistry(use_prometheus)
    _tracer = OpenTelemetryTracer(otlp_endpoint=otlp_endpoint)


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Initialize
    init_monitoring(use_prometheus=PROMETHEUS_AVAILABLE)
    
    metrics = get_metrics()
    tracer = get_tracer()
    
    # Test metrics
    labels = MetricLabels(
        agent_id="agent_001",
        agent_class="coding",
        plan_id="plan_001",
        step_id="step_001",
        autonomy_level="2",
        trust_level="UNRESTRICTED",
    )
    
    # Record some metrics
    metrics.record_authz_request(labels, "permit", 0.025)
    metrics.record_plan_created(labels)
    metrics.record_step(labels, "file_write", "success", 0.012)
    metrics.record_consent(labels, "medium", "approved", 1.5)
    metrics.record_token_created(labels, "step")
    metrics.record_token_validation(labels, True)
    metrics.record_pep_enforcement("fs", "file_write", "allow", 0.003)
    metrics.update_trust_score("agent_001", "coding", 75.5)
    metrics.update_trust_level("agent_001", "coding", 2)
    metrics.update_effective_autonomy("agent_001", "coding", 2)
    
    print("Metrics recorded successfully")
    
    # Print Prometheus output
    prom_output = metrics.get_prometheus_metrics()
    print(f"\nPrometheus metrics ({len(prom_output)} bytes):")
    print(prom_output.decode()[:2000])
    
    # Test tracing
    with tracer.trace_operation("test_operation", {"agent_id": "agent_001"}) as span:
        if hasattr(span, 'set_attribute'):
            span.set_attribute("test_key", "test_value")
        print("Tracing operation completed")