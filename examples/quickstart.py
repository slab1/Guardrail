#!/usr/bin/env python3
"""Quickstart example for Guardrail."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from guardrail import GuardrailAgent

def main():
    print("=== Guardrail Quickstart ===\n")
    
    # Create a coding agent with L2 autonomy (read/write/execute)
    agent = GuardrailAgent(
        agent_class="coding",
        user_id="developer_001",
        autonomy_level=2,  # L2: read/write/execute
    )
    
    # Define the task in natural language
    intent = "Create a configuration file config.yaml in /tmp/guardrail_demo/ with database settings, then validate it exists"
    
    print(f"Intent: {intent}\n")
    print("Executing plan...")
    
    # Execute the plan
    result = agent.run(intent, plan_id="demo_001")
    
    # Print results
    print(f"\nPlan ID: {result.plan_id}")
    print(f"Description: {result.plan_description}")
    print(f"Consent given: {result.consent_given}")
    print(f"Steps executed: {len(result.step_results)}")
    print(f"Success: {not result.error}")
    
    if result.error:
        print(f"Error: {result.error}")
    
    for step_result in result.step_results:
        print(f"  - {step_result}")
    
    print("\n=== Quickstart Complete ===")

if __name__ == "__main__":
    main()