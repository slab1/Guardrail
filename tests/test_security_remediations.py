import os
import sys
import asyncio
import pytest
from fastapi import HTTPException, Request

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import (
    app,
    active_plans,
    decide_consent,
    ConsentDecisionRequest,
    get_current_principal,
    Principal,
    export_compliance_bundle,
    verify_pep_token,
    PepVerifyRequest
)

def test_consent_blocked_when_pending_semantic():
    plan_id = "test_pending_semantic_plan"
    active_plans[plan_id] = {
        "id": plan_id,
        "intent": "Read sensitive config",
        "description": "Read sensitive config",
        "status": "pending_semantic",
        "user_id": "test_user",
        "tenant_id": "tenant-secops",
        "steps": [{"id": "step_1", "action": "file_read", "resource": "/workspace/config"}],
        "created_at": 10000000000.0,
        "plan_hash": "dummy_hash_123"
    }

    principal = Principal(user_id="dev_approver", tenant_id="tenant-secops", role="approver", email="approver@guardrail.internal")
    req = ConsentDecisionRequest(
        plan_id=plan_id,
        approved=True,
        step_approvals={"step_1": True},
        plan_hash="dummy_hash_123"
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(decide_consent(req, principal))

    assert exc_info.value.status_code == 400
    assert "semantic safety check is pending or failed" in exc_info.value.detail

def test_unauthenticated_request_raises_in_production(monkeypatch):
    monkeypatch.setenv("GUARDRAIL_ENV", "production")
    
    # Mock request without Authorization header
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/compliance/export",
        "headers": []
    }
    request = Request(scope)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(get_current_principal(request))

    assert exc_info.value.status_code == 401
    assert "Missing Authorization Bearer token" in exc_info.value.detail
