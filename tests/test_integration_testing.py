"""Tests for the Integration Testing module."""
"""Tests for the Integration Testing module."""
import sys
import os
import time
import json
import asyncio

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
pytestmark = pytest.mark.asyncio

from integration_testing import (
    IntegrationTestRunner, IntegrationTestSuite, IntegrationTestCase, IntegrationTestResult,
    IntegrationTestStatus, TestSeverity,
    create_mcp_integration_suite, create_langgraph_integration_suite,
    create_nemotron_integration_suite, create_cross_component_suite,
    create_standard_suites, create_runner,
    _test_mcp_connection, _test_mcp_tool_listing, _test_mcp_tool_execution,
    _test_langgraph_workflow, _test_nemotron_function_calling,
    _test_full_pipeline, _test_mesh_communication,
)


def test_integration_test_case_creation():
    """Test creating an integration test case."""
    from integration_testing import IntegrationTestCase, TestSeverity
    
    test = IntegrationTestCase(
        test_id="test_001",
        name="Test Case",
        description="Test description",
        category="test",
        severity=TestSeverity.HIGH,
        test_fn=lambda: None,
    )
    assert test.test_id == "test_001"
    assert test.severity == TestSeverity.HIGH


def test_integration_test_suite_creation():
    """Test creating an integration test suite."""
    from integration_testing import IntegrationTestSuite
    
    suite = IntegrationTestSuite(
        suite_id="suite_001",
        name="Test Suite",
        description="Test suite description",
    )
    assert suite.suite_id == "suite_001"
    assert suite.name == "Test Suite"


def test_mcp_integration_suite():
    """Test MCP integration suite creation."""
    suite = create_mcp_integration_suite()
    assert suite.suite_id == "mcp_integration"
    assert len(suite.tests) == 3
    assert all(t.category == "mcp" for t in suite.tests)


def test_langgraph_integration_suite():
    """Test LangGraph integration suite creation."""
    suite = create_langgraph_integration_suite()
    assert suite.suite_id == "langgraph_integration"
    assert len(suite.tests) == 1
    assert suite.tests[0].category == "langgraph"


def test_nemotron_integration_suite():
    """Test Nemotron integration suite creation."""
    suite = create_nemotron_integration_suite()
    assert suite.suite_id == "nemotron_integration"
    assert len(suite.tests) == 1
    assert suite.tests[0].category == "nemotron"


def test_cross_component_suite():
    """Test cross-component suite creation."""
    suite = create_cross_component_suite()
    assert suite.suite_id == "cross_component"
    assert len(suite.tests) == 2
    assert all(t.category == "cross_component" for t in suite.tests)


def test_standard_suites():
    """Test creating standard suites."""
    suites = create_standard_suites()
    assert "mcp" in suites
    assert "langgraph" in suites
    assert "nemotron" in suites
    assert "cross_component" in suites


def test_create_runner():
    """Test creating a test runner."""
    runner = create_runner()
    assert runner is not None
    assert len(runner.suites) == 4


async def test_mcp_connection():
    """Test MCP connection test function."""
    result = await _test_mcp_connection()
    assert result["status"] == "connected"


async def test_mcp_tool_listing():
    """Test MCP tool listing test function."""
    result = await _test_mcp_tool_listing()
    assert "tools" in result
    assert len(result["tools"]) > 0


async def test_mcp_tool_execution():
    """Test MCP tool execution test function."""
    result = await _test_mcp_tool_execution()
    assert result["executed"] == "file_write"
    assert result["guardrail_allowed"] is True


async def test_langgraph_workflow():
    """Test LangGraph workflow test function."""
    result = await _test_langgraph_workflow()
    assert result["workflow"] == "test"
    assert result["guardrail_enforced"] is True


async def test_nemotron_function_calling():
    """Test Nemotron function calling test function."""
    result = await _test_nemotron_function_calling()
    assert result["functions_called"] == ["guardrail_execute_plan"]
    assert result["validated"] is True


async def test_full_pipeline():
    """Test full pipeline test function."""
    result = await _test_full_pipeline()
    assert result["plan_compiled"] is True
    assert result["consent_given"] is True
    assert result["steps_executed"] == 3
    assert result["audit_logged"] is True


async def test_mesh_communication():
    """Test mesh communication test function."""
    result = await _test_mesh_communication()
    assert result["nodes_connected"] == 3
    assert result["messages_exchanged"] == 10
    assert result["consensus_reached"] is True


async def test_integration_runner():
    """Test integration test runner."""
    runner = IntegrationTestRunner()
    
    suite = IntegrationTestSuite(
        suite_id="test_suite",
        name="Test Suite",
        description="Test suite for testing",
    )
    
    async def sample_test():
        await asyncio.sleep(0.01)
        return "success"
    
    test = IntegrationTestCase(
        test_id="test_001",
        name="Sample Test",
        description="Sample test",
        category="test",
        severity=None,
        test_fn=sample_test,
    )
    
    runner.add_suite(IntegrationTestSuite(
        suite_id="test_suite",
        name="Test Suite",
        description="Test suite",
        tests=[IntegrationTestCase(
            test_id="test_001",
            name="Sample Test",
            description="Sample",
            category="test",
            severity=None,
            test_fn=sample_test,
        )]
    ))
    
    result = await runner.run_suite("test_suite")
    assert result.completed_at is not None
    assert len(result.results) == 1
    assert result.results[0].status.value == "passed"


async def test_integration_runner_multiple_suites():
    """Test running multiple suites."""
    runner = IntegrationTestRunner()
    
    async def sample_test():
        await asyncio.sleep(0.01)
        return "success"
    
    suite1 = IntegrationTestSuite(
        suite_id="suite_1",
        name="Suite 1",
        description="Suite 1",
        tests=[IntegrationTestCase(
            test_id="t1", name="Test 1", description="", category="test",
            severity=None, test_fn=lambda: asyncio.sleep(0.01)
        )]
    )
    
    suite2 = IntegrationTestSuite(
        suite_id="suite_2",
        name="Suite 2",
        description="Suite 2",
        tests=[IntegrationTestCase(
            test_id="t2", name="Test 2", description="", category="test",
            severity=None, test_fn=lambda: asyncio.sleep(0.01)
        )]
    )
    
    runner.add_suite(suite1)
    runner.add_suite(suite2)
    
    results = await runner.run_all()
    
    assert "suite_1" in runner.suites
    assert "suite_2" in runner.suites
    assert len(runner.suites) == 2


def test_report_generation():
    """Test report generation."""
    import time
    from integration_testing import IntegrationTestRunner, IntegrationTestSuite, IntegrationTestResult, IntegrationTestStatus
    
    runner = IntegrationTestRunner()
    
    suite = IntegrationTestSuite(
        suite_id="test_suite",
        name="Test Suite",
        description="Test suite",
    )
    
    # Add some mock results
    suite.results = [
        IntegrationTestResult(
            test_id="test_1",
            name="Test 1",
            status=IntegrationTestStatus.PASSED,
            started_at=time.time() - 10,
            completed_at=time.time(),
            duration_seconds=10.0,
        ),
        IntegrationTestResult(
            test_id="test_2",
            name="Test 2",
            status=IntegrationTestStatus.FAILED,
            started_at=time.time() - 5,
            completed_at=time.time(),
            duration_seconds=5.0,
            error="Test failed",
        ),
    ]
    
    runner = IntegrationTestRunner()
    report = runner.generate_report(suite)
    
    assert report["total_tests"] == 2
    assert report["passed"] == 1
    assert report["failed"] == 1
    assert report["success_rate"] == 0.5


def test_report_export_json():
    """Test JSON report export."""
    runner = IntegrationTestRunner()
    suite = IntegrationTestSuite(
        suite_id="test_suite",
        name="Test Suite",
        description="Test suite",
    )
    suite.results = [
        IntegrationTestResult(
            test_id="test_1",
            name="Test 1",
            status=IntegrationTestStatus.PASSED,
            started_at=time.time() - 10,
            completed_at=time.time(),
            duration_seconds=10.0,
        ),
    ]
    
    runner = IntegrationTestRunner()
    json_output = runner.export_report(suite, "json")
    import json
    parsed = json.loads(json_output)
    assert parsed["total_tests"] == 1
    assert parsed["passed"] == 1


def test_report_export_junit():
    """Test JUnit XML report export."""
    runner = IntegrationTestRunner()
    suite = IntegrationTestSuite(
        suite_id="test_suite",
        name="Test Suite",
        description="Test suite",
    )
    suite.results = [
        IntegrationTestResult(
            test_id="test_1",
            name="Test 1",
            status=IntegrationTestStatus.PASSED,
            started_at=time.time() - 10,
            completed_at=time.time(),
            duration_seconds=10.0,
        ),
    ]
    
    runner = IntegrationTestRunner()
    xml_output = runner.export_report(suite, "junit")
    assert "<?xml version=" in xml_output
    assert "<testsuite" in xml_output
    assert "testcase" in xml_output


def test_create_standard_suites():
    """Test creating standard suites."""
    suites = create_standard_suites()
    assert len(suites) == 4
    assert "mcp" in suites
    assert "langgraph" in suites
    assert "nemotron" in suites
    assert "cross_component" in suites


def test_create_runner():
    """Test creating a runner with standard suites."""
    runner = create_runner()
    assert len(runner.suites) == 4


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])