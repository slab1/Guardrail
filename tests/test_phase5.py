"""Tests for Phase 5: Monitoring, Compliance, Scaling, Deployment."""
import sys
import os
import tempfile
import time

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from monitoring import (
    MetricsRegistry, MetricLabels, MockCounter, MockHistogram, MockGauge,
    OpenTelemetryTracer, get_metrics, init_monitoring
)
from compliance import (
    ComplianceReporter, ComplianceFramework, ComplianceControl, ControlStatus,
    ComplianceReport, get_compliance_reporter, generate_compliance_report
)


# ----------------------------------------------------------------------
# Monitoring Tests
# ----------------------------------------------------------------------
def test_metrics_registry_creation():
    """Test metrics registry creation."""
    registry = MetricsRegistry(use_prometheus=False)
    assert registry is not None
    assert registry.use_prometheus is False


def test_mock_counter():
    """Test mock counter functionality."""
    counter = MockCounter("test", "Test counter", ["label1"])
    counter.inc()
    assert counter.value == 1
    
    labeled = counter.labels(label1="value1")
    labeled.inc()
    labeled.inc(5)
    # label_key is tuple of sorted kwargs items
    key = (("label1", "value1"),)
    assert counter.labels_dict[key] == 6


def test_mock_histogram():
    """Test mock histogram functionality."""
    histogram = MockHistogram("test", "Test histogram", ["label1"])
    histogram.observe(0.5)
    histogram.observe(1.2)
    assert len(histogram.observations) == 2
    assert 0.5 in histogram.observations
    assert 1.2 in histogram.observations
    
    # Test timer
    timer = histogram.time()
    time.sleep(0.01)
    timer.__exit__()
    assert len(histogram.observations) == 3


def test_mock_gauge():
    """Test mock gauge functionality."""
    gauge = MockGauge("test", "Test gauge", ["label1"])
    gauge.set(10.0)
    assert gauge.value == 10.0
    
    gauge.inc(5.0)
    assert gauge.value == 15.0
    
    gauge.dec(3.0)
    assert gauge.value == 12.0
    
    labeled = gauge.labels(label1="value1")
    labeled.set(20.0)
    key = (("label1", "value1"),)
    assert gauge.labels_dict[key] == 20.0


def test_metrics_recording():
    """Test metrics recording functions."""
    registry = MetricsRegistry(use_prometheus=False)
    
    labels = MetricLabels(
        agent_id="agent_001",
        agent_class="coding",
        plan_id="plan_001",
        step_id="step_001",
        autonomy_level="2",
        trust_level="UNRESTRICTED",
    )
    
    # Record various metrics
    registry.record_authz_request(labels, "permit", 0.025)
    registry.record_plan_created(labels)
    registry.record_plan_executed(labels, 5.5)
    registry.record_step(labels, "file_write", "success", 0.012)
    registry.record_consent(labels, "medium", "approved", 1.5)
    registry.record_token_created(labels, "step")
    registry.record_token_validation(labels, True)
    registry.record_pep_enforcement("fs", "file_write", "allow", 0.003)
    registry.update_trust_score("agent_001", "coding", 75.5)
    registry.update_trust_level("agent_001", "coding", 2)
    registry.update_effective_autonomy("agent_001", "coding", 2)
    registry.set_active_agents(5)
    registry.record_error("test", "test_error")
    
    # Check Prometheus output
    output = registry.get_prometheus_metrics()
    assert isinstance(output, bytes)
    assert len(output) > 0


def test_opentelemetry_tracer():
    """Test OpenTelemetry tracer (mock)."""
    tracer = OpenTelemetryTracer("test-service")
    
    # Test span creation
    span = tracer.start_span("test_operation", {"key": "value"})
    assert span is not None
    
    # Test context manager
    with tracer.trace_operation("test_op", {"attr": "value"}) as span:
        assert span is not None
        if hasattr(span, 'set_attribute'):
            span.set_attribute("test", "value")


def test_global_metrics():
    """Test global metrics functions."""
    init_monitoring(use_prometheus=False)
    metrics = get_metrics()
    assert metrics is not None
    assert isinstance(metrics, MetricsRegistry)


# ----------------------------------------------------------------------
# Compliance Tests
# ----------------------------------------------------------------------
def test_compliance_reporter_creation():
    """Test compliance reporter creation."""
    reporter = ComplianceReporter()
    assert reporter is not None
    assert len(reporter.controls) > 0


def test_compliance_control_creation():
    """Test compliance control creation."""
    control = ComplianceControl(
        control_id="TEST-01",
        framework=ComplianceFramework.EU_AI_ACT,
        title="Test Control",
        description="Test description",
        category="Testing",
    )
    assert control.control_id == "TEST-01"
    assert control.framework == ComplianceFramework.EU_AI_ACT
    assert control.status == ControlStatus.NOT_IMPLEMENTED


def test_assess_control():
    """Test control assessment."""
    reporter = ComplianceReporter()
    
    # Add a test control
    control = ComplianceControl(
        control_id="TEST-02",
        framework=ComplianceFramework.NIST_800_53,
        title="Test Control 2",
        description="Test",
        category="Test",
    )
    reporter.controls["TEST-02"] = control
    
    # Assess it
    result = reporter.assess_control(
        "TEST-02",
        ControlStatus.IMPLEMENTED,
        evidence=["test_evidence.txt"],
        notes="Test notes",
        assessor="tester",
    )
    assert result is True
    
    assessed = reporter.controls["TEST-02"]
    assert assessed.status == ControlStatus.IMPLEMENTED
    assert assessed.evidence == ["test_evidence.txt"]
    assert assessed.implementation_notes == "Test notes"
    assert assessed.assessor == "tester"


def test_auto_assess():
    """Test automatic control assessment."""
    reporter = ComplianceReporter()
    reporter.auto_assess_controls()
    
    # Check that some controls were assessed
    implemented_count = sum(
        1 for c in reporter.controls.values()
        if c.status == ControlStatus.IMPLEMENTED
    )
    assert implemented_count > 0


def test_generate_report():
    """Test compliance report generation."""
    reporter = ComplianceReporter()
    reporter.auto_assess_controls()
    
    report = reporter.generate_report(ComplianceFramework.EU_AI_ACT)
    
    assert isinstance(report, ComplianceReport)
    assert report.framework == ComplianceFramework.EU_AI_ACT
    assert report.report_id is not None
    assert "compliance_rate" in report.summary
    assert "total_controls" in report.summary


def test_export_report_json():
    """Test JSON report export."""
    reporter = ComplianceReporter()
    reporter.auto_assess_controls()
    
    report = reporter.generate_report(ComplianceFramework.NIST_800_53)
    json_output = reporter.export_report(report, "json")
    
    import json
    parsed = json.loads(json_output)
    assert "report_id" in parsed
    assert "framework" in parsed
    assert "summary" in parsed
    assert "controls" in parsed


def test_export_report_csv():
    """Test CSV report export."""
    reporter = ComplianceReporter()
    reporter.auto_assess_controls()
    
    report = reporter.generate_report(ComplianceFramework.ISO_27001)
    csv_output = reporter.export_report(report, "csv")
    
    assert "control_id,title,category,status" in csv_output
    lines = csv_output.strip().split("\n")
    assert len(lines) > 1  # Header + at least one control


def test_all_frameworks_status():
    """Test getting status for all frameworks."""
    reporter = ComplianceReporter()
    reporter.auto_assess_controls()
    
    status = reporter.get_all_frameworks_status()
    
    assert ComplianceFramework.EU_AI_ACT.value in status
    assert ComplianceFramework.NIST_800_53.value in status
    assert ComplianceFramework.ISO_27001.value in status
    
    for fw_status in status.values():
        assert "compliance_rate" in fw_status
        assert "total_controls" in fw_status


def test_global_compliance_reporter():
    """Test global compliance reporter."""
    reporter = get_compliance_reporter()
    assert reporter is not None


def test_generate_compliance_report():
    """Test convenience function."""
    report = generate_compliance_report(ComplianceFramework.EU_AI_ACT)
    assert isinstance(report, ComplianceReport)


# ----------------------------------------------------------------------
# Run tests
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])