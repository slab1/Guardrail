import sys
import os
import pytest

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from guardrail.formal_verification.verifier import create_verifier

def test_file_read_policy():
    verifier = create_verifier()
    policy = "action == 'file_read' AND resource.startswith('/workspace/')"
    
    # Positive case
    assert verifier.verify_policy(policy, {"action": "file_read", "resource": "/workspace/data.txt"}) == True
    
    # Negative case: wrong action
    assert verifier.verify_policy(policy, {"action": "file_write", "resource": "/workspace/data.txt"}) == False
    
    # Negative case: wrong resource
    assert verifier.verify_policy(policy, {"action": "file_read", "resource": "/etc/passwd"}) == False

def test_cache_performance():
    verifier = create_verifier()
    policy = "action == 'file_read' AND resource.startswith('/workspace/')"
    context = {"action": "file_read", "resource": "/workspace/test.txt"}
    
    import time
    
    # First call (cold)
    start = time.perf_counter()
    verifier.verify_policy(policy, context)
    cold_time = time.perf_counter() - start
    
    # Second call (hot/cached)
    start = time.perf_counter()
    verifier.verify_policy(policy, context)
    hot_time = time.perf_counter() - start
    
    # Hot should be significantly faster (targeting <1ms)
    assert hot_time < 0.001
    assert hot_time < cold_time

def test_resource_boundary_cases():
    verifier = create_verifier()
    policy = "resource.startswith('/workspace/')"
    
    # Edge case: empty resource
    assert verifier.verify_policy(policy, {"resource": ""}) == False
    
    # Edge case: prefix but not exactly directory
    assert verifier.verify_policy(policy, {"resource": "/workspace_secret/"}) == False
    
    # Valid
    assert verifier.verify_policy(policy, {"resource": "/workspace/sub/dir/"}) == True
