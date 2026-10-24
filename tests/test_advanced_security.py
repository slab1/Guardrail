"""Tests for the Advanced Security module."""
import sys
import os
import time
import tempfile

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from advanced_security import (
    AdvancedSecurityManager,
    BiometricProvider, BiometricType, BiometricStatus,
    BiometricTemplate, BiometricVerificationResult,
    HSMProvider, HSMStatus, HSMKey, HSMSignatureRequest, HSMSignatureResponse,
    VerificationEngine, VerificationStatus,
    MockBiometricProvider, MockHSMProvider, MockVerificationEngine,
    create_advanced_security_manager,
    BiometricVerificationResult,
)


def test_mock_biometric_provider():
    """Test mock biometric provider."""
    provider = MockBiometricProvider()
    
    # Enroll
    template = provider.enroll("user_001", b"fingerprint_data", BiometricType.FINGERPRINT)
    assert template.template_id.startswith("bio_")
    assert template.user_id == "user_001"
    assert template.biometric_type == BiometricType.FINGERPRINT
    
    # Verify
    result = provider.verify("user_001", b"fingerprint_data", BiometricType.FINGERPRINT)
    assert result.status == BiometricStatus.VERIFIED
    assert result.confidence >= 0.95
    assert result.template_id is not None
    
    # Verify non-enrolled user
    result = provider.verify("user_999", b"fingerprint_data", BiometricType.FINGERPRINT)
    assert result.status == BiometricStatus.NOT_ENROLLED
    
    # List templates
    templates = provider.list_templates("user_001")
    assert len(templates) == 1
    assert templates[0].template_id == template.template_id
    
    # Delete template
    deleted = provider.delete_template(template.template_id)
    assert deleted is True
    
    templates = provider.list_templates("user_001")
    assert len(templates) == 0


def test_mock_hsm_provider():
    """Test mock HSM provider."""
    provider = MockHSMProvider()
    
    # Initialize
    status = provider.initialize()
    assert status == HSMStatus.CONNECTED
    assert provider.get_status() == HSMStatus.CONNECTED
    
    # Generate key
    key = provider.generate_key("RSA", 2048, "signing")
    assert key.key_id.startswith("key_")
    assert key.algorithm == "RSA"
    assert key.key_size == 2048
    assert key.purpose == "signing"
    
    # Sign data
    request = HSMSignatureRequest(
        request_id="req_001",
        key_id=key.key_id,
        data=b"test data",
        algorithm="RSA-PSS-SHA256",
    )
    response = provider.sign(request)
    assert response.status == HSMStatus.CONNECTED
    assert response.signature is not None
    assert len(response.signature) == 32  # SHA256
    
    # Sign with invalid key
    bad_request = HSMSignatureRequest(
        request_id="req_002",
        key_id="invalid_key",
        data=b"test",
        algorithm="RSA",
    )
    bad_response = provider.sign(bad_request)
    assert bad_response.status == HSMStatus.ERROR
    assert bad_response.error == "Key not found"
    
    # Encrypt/decrypt
    encrypted = provider.encrypt(key.key_id, b"secret data")
    decrypted = provider.decrypt(key.key_id, encrypted)
    assert decrypted == b"secret data"
    
    # Close
    provider.close()
    assert provider.get_status() == HSMStatus.DISCONNECTED


def test_mock_verification_engine():
    """Test mock verification engine."""
    engine = MockVerificationEngine()
    
    # Verify model
    result = engine.verify_model("model.pml", ["safety", "liveness", "deadlock_freedom"])
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert result["properties_checked"] == 3
    assert all(v == "PASS" for v in result["results"].values())
    
    # Verify code
    result = engine.verify_code("code.py", "spec.md")
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert result["checks_passed"] is True
    
    # Check invariants
    result = engine.check_invariants({"x": 1}, ["x > 0", "x < 10"])
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert len(result["results"]) == 2


def test_advanced_security_manager():
    """Test advanced security manager."""
    manager = create_advanced_security_manager()
    
    # Test biometric enrollment
    template = manager.enroll_biometric(
        user_id="user_001",
        biometric_data=b"fingerprint_data",
        biometric_type=BiometricType.FINGERPRINT,
    )
    assert template.template_id is not None
    assert template.user_id == "user_001"
    assert template.biometric_type == BiometricType.FINGERPRINT
    
    # Test biometric verification
    result = manager.verify_biometric(
        user_id="user_001",
        biometric_data=b"fingerprint_data",
        biometric_type=BiometricType.FINGERPRINT,
    )
    assert result.status == BiometricStatus.VERIFIED
    assert result.confidence >= 0.95
    
    # Test secure action workflow - low risk (no biometric)
    result = manager.secure_action_workflow(
        user_id="user_001",
        action="read_file",
        risk_level="low",
    )
    assert result["allowed"] is True
    assert result["biometric_required"] is False
    
    # Test secure action workflow - high risk (biometric required)
    result = manager.secure_action_workflow(
        user_id="user_001",
        action="delete_critical_file",
        risk_level="critical",
        biometric_type=BiometricType.FINGERPRINT,
    )
    assert result["biometric_required"] is True
    assert result["allowed"] is True  # Mock biometric verification succeeds
    assert result["biometric_result"]["status"] == "verified"
    
    # Test HSM key generation
    key = manager.generate_hsm_key(algorithm="RSA", key_size=2048, purpose="signing")
    assert key.key_id.startswith("key_")
    assert key.algorithm == "RSA"
    assert key.key_size == 2048
    
    # Test HSM signing
    sign_result = manager.hsm_sign(key.key_id, b"test data")
    assert sign_result.status == HSMStatus.CONNECTED
    assert sign_result.signature is not None
    
    # Test HSM encryption/decryption
    encrypted = manager.hsm_encrypt(key.key_id, b"secret")
    decrypted = manager.hsm_decrypt(key.key_id, encrypted)
    assert decrypted == b"secret"
    
    # Test formal verification
    verification = manager.verify_model("model.pml", ["safety", "liveness"])
    assert verification["status"] == VerificationStatus.VERIFIED.value
    
    # Test code verification
    verification = manager.verify_code("code.py", "spec.md")
    assert verification["status"] == VerificationStatus.VERIFIED.value
    
    # Test invariants
    verification = manager.check_invariants({"x": 5}, ["x > 0", "x < 10"])
    assert verification["status"] == VerificationStatus.VERIFIED.value
    
    # Get HSM status
    status = manager.get_hsm_status()
    assert status == HSMStatus.CONNECTED
    
    # Get biometric templates
    templates = manager.get_biometric_templates("user_001")
    assert len(templates) >= 1


def test_biometric_types():
    """Test all biometric types."""
    manager = create_advanced_security_manager()
    
    for bio_type in BiometricType:
        template = manager.enroll_biometric(
            user_id="user_001",
            biometric_data=f"data_{bio_type.value}".encode(),
            biometric_type=bio_type,
        )
        assert template.biometric_type == bio_type
        
        result = manager.verify_biometric(
            user_id="user_001",
            biometric_data=f"data_{bio_type.value}".encode(),
            biometric_type=bio_type,
        )
        assert result.status == BiometricStatus.VERIFIED


def test_hsm_key_purposes():
    """Test HSM key generation for different purposes."""
    manager = create_advanced_security_manager()
    
    purposes = ["signing", "encryption", "key_wrapping", "authentication"]
    algorithms = [("RSA", 2048), ("RSA", 4096), ("ECDSA", 256), ("AES", 256)]
    
    for purpose in purposes:
        for algorithm, key_size in algorithms:
            if algorithm == "AES" and purpose == "signing":
                continue  # AES not for signing
            key = manager.generate_hsm_key(algorithm, key_size, purpose)
            assert key.purpose == purpose
            assert key.algorithm == algorithm
            assert key.key_size == key_size


def test_formal_verification_invariants():
    """Test invariant checking."""
    manager = create_advanced_security_manager()
    
    # System state with invariants
    state = {
        "balance": 1000,
        "transactions": 5,
        "locked": False,
    }
    
    invariants = [
        "balance >= 0",
        "transactions >= 0",
        "not locked or balance > 0",
    ]
    
    result = manager.check_invariants(state, invariants)
    assert result["status"] == VerificationStatus.VERIFIED.value
    assert result["invariants_checked"] == 3


def test_hsm_key_lifecycle():
    """Test HSM key import/export cycle."""
    manager = create_advanced_security_manager()
    
    # Generate key
    key1 = manager.generate_hsm_key("RSA", 2048, "signing")
    
    # Import key (mock)
    key2 = manager.hsm_provider.import_key("imported_key_001", b"key_data", "RSA")
    assert key2.key_id == "imported_key_001"
    assert key2.algorithm == "RSA"
    
    # Sign with imported key
    result = manager.hsm_sign(key2.key_id, b"test")
    assert result.status == HSMStatus.CONNECTED


def test_biometric_confidence_thresholds():
    """Test biometric confidence thresholds."""
    manager = create_advanced_security_manager()
    
    # Enroll
    manager.enroll_biometric("user_001", b"fingerprint", BiometricType.FINGERPRINT)
    
    # Test with different risk levels
    low_result = manager.secure_action_workflow("user_001", "read", "low")
    assert low_result["biometric_required"] is False
    
    medium_result = manager.secure_action_workflow("user_001", "write", "medium", BiometricType.FINGERPRINT)
    assert medium_result["biometric_required"] is True
    
    high_result = manager.secure_action_workflow("user_001", "delete", "high", BiometricType.FINGERPRINT)
    assert high_result["biometric_required"] is True
    
    critical_result = manager.secure_action_workflow("user_001", "admin_delete", "critical", BiometricType.FINGERPRINT)
    assert critical_result["biometric_required"] is True


def test_hsm_status_transitions():
    """Test HSM status transitions."""
    provider = MockHSMProvider()
    
    assert provider.get_status() == HSMStatus.DISCONNECTED
    
    status = provider.initialize()
    assert status == HSMStatus.CONNECTED
    
    provider.close()
    assert provider.get_status() == HSMStatus.DISCONNECTED


def test_verification_statuses():
    """Test all verification statuses."""
    engine = MockVerificationEngine()
    
    # Test model verification
    result = engine.verify_model("test.pml", ["prop1"])
    assert result["status"] == "verified"
    
    # Test code verification
    result = engine.verify_code("code.py", "spec.md")
    assert result["status"] == "verified"
    
    # Test invariant checking
    result = engine.check_invariants({}, ["inv1"])
    assert result["status"] == "verified"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])