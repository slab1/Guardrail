#!/usr/bin/env python3
"""LangGraph integration example for Guardrail."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from guardrail.langgraph_adapter import LangGraphAdapter

def main():
    print("=== Guardrail + LangGraph Integration ===\n")
    
    # Create LangGraph adapter
    adapter = LangGraphAdapter(
        agent_class="coding",
        user_id="langgraph_user",
        autonomy_level=2,
    )
    
    # Define intent
    intent = "Create a Python script that prints hello world, then run it"
    
    print(f"Intent: {intent}\n")
    print("Building and running LangGraph workflow...")
    
    # Run the workflow
    result = adapter.run(intent)
    
    # Print results
    print(f"\nPlan: {result.plan.id if result.plan else 'None'}")
    print(f"Consent given: {result.consent_given}")
    print(f"Steps executed: {len(result.step_results)}")
    print(f"Error: {result.error}")
    
    for r in result.step_results:
        print(f"  - {r}")

if __name__ == "__main__":
    main()