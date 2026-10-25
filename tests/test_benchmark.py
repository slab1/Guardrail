"""Tests for the Benchmark Framework."""
import sys
import os
import time

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from benchmark import (
    BenchmarkRunner, BenchmarkTask, TaskExecution, BenchmarkResult,
    BenchmarkTaskType, SupervisionApproach, TaskOutcome,
    run_standard_benchmark
)


def test_benchmark_runner_creation():
    """Test benchmark runner creation."""
    runner = BenchmarkRunner()
    assert runner is not None
    assert len(runner.tasks) > 0


def test_default_tasks_loaded():
    """Test that default tasks are loaded."""
    runner = BenchmarkRunner()
    
    # Check we have tasks of different types
    task_types = set(t.task_type for t in runner.tasks)
    assert BenchmarkTaskType.FILE_OPERATIONS in task_types
    assert BenchmarkTaskType.NETWORK_REQUESTS in task_types
    assert BenchmarkTaskType.SHELL_COMMANDS in task_types
    assert BenchmarkTaskType.COMPLEX_WORKFLOW in task_types
    assert BenchmarkTaskType.ADVERSARIAL in task_types
    
    # Check we have both safe and risky tasks
    safe_tasks = [t for t in runner.tasks if t.should_succeed]
    risky_tasks = [t for t in runner.tasks if not t.should_succeed]
    assert len(safe_tasks) > 0
    assert len(risky_tasks) > 0
    
    # Check adversarial tasks
    adv_tasks = [t for t in runner.tasks if t.adversarial]
    assert len(adv_tasks) > 0


def test_add_custom_task():
    """Test adding custom task."""
    runner = BenchmarkRunner()
    initial_count = len(runner.tasks)
    
    custom_task = BenchmarkTask(
        task_id="custom_001",
        task_type="custom",
        description="Custom test task",
        intent="Do something custom",
        expected_actions=[{"action": "custom_action", "resource": "test"}],
        risk_level="low",
    )
    
    runner.add_task(custom_task)
    assert len(runner.tasks) == initial_count + 1
    assert runner.tasks[-1].task_id == "custom_001"


def test_simulate_execution_no_supervision():
    """Test simulation with no supervision."""
    runner = BenchmarkRunner()
    task = runner.tasks[0]  # First task (should be safe)
    
    execution = runner._simulate_execution(
        task, SupervisionApproach.NO_SUPERVISION, "agent_001", "exec_001", time.time()
    )
    
    assert execution.approach == SupervisionApproach.NO_SUPERVISION
    assert execution.outcome == TaskOutcome.SUCCESS
    assert execution.consent_requests == 0
    assert execution.tokens_generated == 0


def test_simulate_execution_per_action():
    """Test simulation with per-action confirmation."""
    runner = BenchmarkRunner()
    task = runner.tasks[0]  # Safe task
    
    execution = runner._simulate_execution(
        task, SupervisionApproach.PER_ACTION_CONFIRM, "agent_001", "exec_001", time.time()
    )
    
    assert execution.approach == SupervisionApproach.PER_ACTION_CONFIRM
    assert execution.outcome == TaskOutcome.SUCCESS
    assert execution.consent_requests == len(task.expected_actions)
    assert execution.consent_approved == len(task.expected_actions)


def test_simulate_execution_plan_level():
    """Test simulation with plan-level consent."""
    runner = BenchmarkRunner()
    task = runner.tasks[0]  # Safe task
    
    execution = runner._simulate_execution(
        task, SupervisionApproach.PLAN_LEVEL, "agent_001", "exec_001", time.time()
    )
    
    assert execution.approach == SupervisionApproach.PLAN_LEVEL
    assert execution.outcome == TaskOutcome.SUCCESS
    assert execution.consent_requests == 1
    assert execution.consent_approved == 1
    assert execution.tokens_generated == len(task.expected_actions) + 1


def test_simulate_execution_guardrail_full():
    """Test simulation with full Guardrail."""
    runner = BenchmarkRunner()
    
    # Safe task
    safe_task = runner.tasks[0]
    execution = runner._simulate_execution(
        safe_task, SupervisionApproach.GUARDRAIL_FULL, "agent_001", "exec_001", time.time()
    )
    
    assert execution.approach == SupervisionApproach.GUARDRAIL_FULL
    assert execution.outcome == TaskOutcome.SUCCESS
    assert execution.consent_requests == 0  # Low risk = auto-approved
    
    # Risky task
    risky_task = next(t for t in runner.tasks if not t.should_succeed)
    execution = runner._simulate_execution(
        risky_task, SupervisionApproach.GUARDRAIL_FULL, "agent_001", "exec_002", time.time()
    )
    
    assert execution.outcome == TaskOutcome.BLOCKED
    assert len(execution.actions_blocked) > 0


def test_run_benchmark():
    """Test running a small benchmark."""
    runner = BenchmarkRunner()
    
    # Run with just a few approaches
    approaches = [
        SupervisionApproach.NO_SUPERVISION,
        SupervisionApproach.GUARDRAIL_FULL,
    ]
    
    results = runner.run_benchmark(approaches=approaches, runs_per_task=1)
    
    assert len(results) == 2
    assert SupervisionApproach.NO_SUPERVISION in results
    assert SupervisionApproach.GUARDRAIL_FULL in results
    
    # Check results structure
    for approach, result in results.items():
        assert isinstance(result, BenchmarkResult)
        assert result.total_tasks > 0
        assert 0 <= result.safety_score <= 100
        assert 0 <= result.efficiency_score <= 100
        assert 0 <= result.overall_score <= 100


def test_benchmark_results_export():
    """Test exporting benchmark results."""
    runner = BenchmarkRunner()
    results = runner.run_benchmark(
        approaches=[SupervisionApproach.NO_SUPERVISION, SupervisionApproach.GUARDRAIL_FULL],
        runs_per_task=1,
    )
    
    # Test JSON export
    json_output = runner.export_results(results, "json")
    import json
    parsed = json.loads(json_output)
    assert "approach_results" in parsed
    assert "executions" in parsed
    
    # Test CSV export
    csv_output = runner.export_results(results, "csv")
    lines = csv_output.strip().split("\n")
    assert len(lines) > 1  # Header + data
    assert "execution_id" in lines[0]


def test_benchmark_task_creation():
    """Test creating benchmark tasks."""
    task = BenchmarkTask(
        task_id="test_001",
        task_type="file_ops",
        description="Test task",
        intent="Test intent",
        expected_actions=[{"action": "file_read", "resource": "/tmp/test"}],
        risk_level="low",
    )
    
    assert task.task_id == "test_001"
    assert task.risk_level == "low"
    assert task.should_succeed is True


def test_task_execution_creation():
    """Test creating task executions."""
    import time
    execution = TaskExecution(
        execution_id="exec_001",
        task_id="task_001",
        approach="guardrail_full",
        agent_id="agent_001",
        start_time=time.time(),
        end_time=time.time() + 1,
        outcome="success",
    )
    
    assert execution.execution_id == "exec_001"
    assert execution.outcome == "success"


def test_benchmark_result_creation():
    """Test creating benchmark results."""
    result = BenchmarkResult(
        approach="guardrail_full",
        total_tasks=10,
        successful_tasks=8,
        failed_tasks=0,
        blocked_tasks=2,
        incorrectly_blocked=0,
        incorrectly_allowed=0,
        avg_execution_time=0.5,
        avg_consent_requests=0.5,
        avg_consent_latency=0.1,
        token_generation_rate=3.0,
        audit_integrity_rate=1.0,
        supervision_overhead=0.1,
        safety_score=95.0,
        efficiency_score=85.0,
        overall_score=91.0,
    )
    
    assert result.approach == "guardrail_full"
    assert result.overall_score == 91.0


def test_run_standard_benchmark():
    """Test the convenience function."""
    results = run_standard_benchmark()
    
    assert len(results) == 4  # All 4 approaches
    for approach in SupervisionApproach:
        assert approach in results


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])