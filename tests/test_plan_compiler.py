"""Tests for the plan compiler module."""
import sys
import os

# Add src to Python path so we can import plan_compiler
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from plan_compiler.plan_compiler import compile_plan, Plan

def test_compile_simple_intent():
    intent = "Create a new file called config.yaml in /etc/ and then run a validation script on it."
    plan = compile_plan(intent, plan_id="test_001")
    assert isinstance(plan, Plan)
    assert len(plan.steps) > 0
    assert plan.model_required == "nvidia/nemotron-3-nano-30b-a3b-reasoning"