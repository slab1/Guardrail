import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, _stored

@pytest.fixture(scope="module")
def client():
    # Set dev super admin auth header for testing
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer dev-super-admin"})
    return c

def test_initial_release_status(client):
    res = client.get("/api/release/status")
    assert res.status_code == 200
    data = res.json()
    assert data["current_stage"] in ["DEVELOPER_PREVIEW", "PRODUCTION_RELEASE"]
    assert len(data["gates"]) == 4

def test_unauthorized_promote_without_approval_rejected(client):
    # Temporarily reset reviews
    _stored.setdefault("release_info", {})["developer_reviews"] = []
    _stored["release_info"]["current_stage"] = "DEVELOPER_PREVIEW"
    
    res = client.post("/api/release/promote", json={"override_warning": False})
    assert res.status_code == 400
    assert "Security Officer Sign-Off" in res.json()["detail"]

def test_submit_developer_review(client):
    payload = {
        "reviewer_name": "Dr. Sarah Chen",
        "reviewer_role": "Principal AI Safety Architect",
        "organization": "Independent Algorithmic Audit Lab",
        "test_suite_verified": True,
        "invariants_verified": True,
        "pep_benchmarks_verified": True,
        "comments": "Verified constant-time HMAC-SHA256 signature verification, linear nonce replay protection, and authoritative SQLite fail-closed revocations. Invariants hold with 0 false positives.",
        "decision": "APPROVED"
    }
    res = client.post("/api/release/review", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "RECORDED"
    assert data["review"]["reviewer_name"] == "Dr. Sarah Chen"
    assert data["review"]["decision"] == "APPROVED"

def test_promote_to_production_after_review(client):
    # Ensure approved review is present (supporting isolated/random test execution)
    status_res = client.get("/api/release/status")
    assert status_res.status_code == 200
    if not status_res.json().get("can_promote"):
        client.post("/api/release/review", json={
            "reviewer_name": "Dr. Sarah Chen",
            "reviewer_role": "Principal AI Safety Architect",
            "organization": "Independent Algorithmic Audit Lab",
            "test_suite_verified": True,
            "invariants_verified": True,
            "pep_benchmarks_verified": True,
            "comments": "Verified constant-time HMAC-SHA256 signature verification.",
            "decision": "APPROVED"
        })
        status_res = client.get("/api/release/status")

    assert status_res.json()["can_promote"] is True

    # Promote to production
    promote_res = client.post("/api/release/promote", json={"release_notes": "Production promotion following verified auditor review."})
    assert promote_res.status_code == 200
    promoted_data = promote_res.json()
    assert promoted_data["status"] == "PROMOTED"
    assert promoted_data["release_info"]["current_stage"] == "PRODUCTION_RELEASE"
    assert promoted_data["release_info"]["version"] == "v2.5.0-GA"
    assert promoted_data["release_info"]["promotion_hash"] is not None

def test_operator_cannot_review_or_promote():
    # Operator client without admin/security_officer role
    op_client = TestClient(app)
    # Default without auth header has role 'operator'
    review_res = op_client.post("/api/release/review", json={
        "reviewer_name": "Unauthorized User",
        "reviewer_role": "Operator",
        "comments": "Should fail",
        "decision": "APPROVED"
    })
    assert review_res.status_code == 403 or review_res.status_code == 400

    promote_res = op_client.post("/api/release/promote", json={})
    assert promote_res.status_code == 403 or promote_res.status_code == 400

def test_rollback_to_developer_preview(client):
    rollback_res = client.post("/api/release/rollback")
    assert rollback_res.status_code == 200
    data = rollback_res.json()
    assert data["status"] == "ROLLED_BACK"
    assert data["release_info"]["current_stage"] == "DEVELOPER_PREVIEW"
