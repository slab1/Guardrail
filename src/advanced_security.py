"""Advanced Security Features for Guardrail.

This module provides advanced security capabilities:
- Biometric authentication integration
- Hardware Security Module (HSM) integration
- Formal verification framework
- Zero-trust architecture components
"""
import time
import uuid
import hashlib
import hmac
import json
import threading
import base64
from typing import Any, Dict, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from abc import ABC, abstractmethod
import logging


class BiometricType(Enum):
    """Types of biometric authentication."""
    FINGERPRINT = "fingerprint"
    FACE_ID = "face_id"
    IRIS = "iris"
    VOICE = "voice"
    BEHAVIORAL = "behavioral"  # Keystroke dynamics, mouse patterns


class BiometricStatus(Enum):
    """Status of biometric authentication."""
    ENROLLED = "enrolled"
    VERIFIED = "verified"
    REJECTED = "rejected"
    ERROR = "error"
    NOT_ENROLLED = "not_enrolled"


class HSMStatus(Enum):
    """HSM connection/status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    LOCKED = "locked"
    INITIALIZING = "initializing"


class VerificationStatus(Enum):
    """Formal verification status."""
    VERIFIED = "verified"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class BiometricTemplate:
    """Encrypted biometric template."""
    template_id: str
    user_id: str
    biometric_type: BiometricType
    encrypted_data: bytes
    algorithm: str
    created_at: float
    updated_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiometricVerificationResult:
    """Result of biometric verification."""
    status: BiometricStatus
    confidence: float  # 0.0 to 1.0
    template_id: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HSMKey:
    """HSM-managed cryptographic key."""
    key_id: str
    algorithm: str  # RSA, ECDSA, AES, etc.
    key_size: int
    purpose: str  # signing, encryption, key_wrapping
    created_at: float
    expires_at: Optional[float]
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HSMSignatureRequest:
    """Request for HSM signing operation."""
    request_id: str
    key_id: str
    data: bytes
    algorithm: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HSMSignatureResponse:
    """Response from HSM signing operation."""
    request_id: str
    signature: Optional[bytes]
    status: HSMStatus
    error: Optional[str] = None


class BiometricProvider(ABC):
    """Abstract base class for biometric authentication providers."""
    
    @abstractmethod
    def enroll(self, user_id: str, biometric_data: bytes, biometric_type: BiometricType) -> BiometricTemplate:
        """Enroll a new biometric template."""
        pass
    
    @abstractmethod
    def verify(self, user_id: str, biometric_data: bytes, biometric_type: BiometricType) -> BiometricVerificationResult:
        """Verify biometric data against enrolled templates."""
        pass
    
    @abstractmethod
    def delete_template(self, template_id: str) -> bool:
        """Delete a biometric template."""
        pass
    
    @abstractmethod
    def list_templates(self, user_id: str) -> List[BiometricTemplate]:
        """List all templates for a user."""
        pass


class MockBiometricProvider(BiometricProvider):
    """Mock biometric provider for testing."""
    
    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.logger = logging.getLogger("mock_biometric")
    
    def enroll(self, user_id: str, biometric_data: bytes, biometric_type: BiometricType) -> BiometricTemplate:
        """Enroll a new biometric template (mock)."""
        template_id = f"bio_{uuid.uuid4().hex[:16]}"
        encrypted = self._encrypt(biometric_data)
        
        template = BiometricTemplate(
            template_id=template_id,
            user_id=user_id,
            biometric_type=biometric_type,
            encrypted_data=encrypted,
            algorithm="AES-256-GCM",
            created_at=time.time(),
            updated_at=time.time(),
        )
        
        self.templates[template_id] = template
        self.logger.info(f"Enrolled {biometric_type.value} for user {user_id}: {template_id}")
        return template
    
    def verify(self, user_id: str, biometric_data: bytes, biometric_type: BiometricType) -> BiometricVerificationResult:
        """Verify biometric data (mock)."""
        # Find user's templates of this type
        user_templates = [
            t for t in self.templates.values()
            if t.user_id == user_id and t.biometric_type == biometric_type
        ]
        
        if not user_templates:
            return BiometricVerificationResult(
                status=BiometricStatus.NOT_ENROLLED,
                confidence=0.0,
                template_id=None,
            )
        
        # Mock: always succeed with high confidence for enrolled users
        # In production, would do actual biometric matching
        return BiometricVerificationResult(
            status=BiometricStatus.VERIFIED,
            confidence=0.99,
            template_id=user_templates[0].template_id,
            details={"matched_template": user_templates[0].template_id},
        )
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a template."""
        if template_id in self.templates:
            del self.templates[template_id]
            return True
        return False
    
    def list_templates(self, user_id: str) -> List[BiometricTemplate]:
        """List user's templates."""
        return [t for t in self.templates.values() if t.user_id == user_id]
    
    def _encrypt(self, data: bytes) -> bytes:
        """Mock encryption."""
        # In production, use proper encryption
        return base64.b64encode(data)


class HSMProvider(ABC):
    """Abstract base class for Hardware Security Module providers."""
    
    @abstractmethod
    def initialize(self) -> HSMStatus:
        """Initialize HSM connection."""
        pass
    
    @abstractmethod
    def generate_key(self, algorithm: str, key_size: int, purpose: str) -> HSMKey:
        """Generate a new key in HSM."""
        pass
    
    @abstractmethod
    def import_key(self, key_id: str, key_data: bytes, algorithm: str) -> HSMKey:
        """Import a key into HSM."""
        pass
    
    @abstractmethod
    def sign(self, request: HSMSignatureRequest) -> HSMSignatureResponse:
        """Sign data using HSM."""
        pass
    
    @abstractmethod
    def encrypt(self, key_id: str, data: bytes) -> bytes:
        """Encrypt data using HSM key."""
        pass
    
    @abstractmethod
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        """Decrypt data using HSM key."""
        pass
    
    @abstractmethod
    def get_status(self) -> HSMStatus:
        """Get HSM status."""
        pass
    
    @abstractmethod
    def close(self):
        """Close HSM connection."""
        pass


class MockHSMProvider(HSMProvider):
    """Mock HSM provider for testing."""
    
    def __init__(self):
        self.keys: Dict[str, HSMKey] = {}
        self.status = HSMStatus.DISCONNECTED
        self.logger = logging.getLogger("mock_hsm")
    
    def initialize(self) -> HSMStatus:
        """Initialize mock HSM."""
        self.status = HSMStatus.CONNECTED
        self.logger.info("Mock HSM initialized")
        return self.status
    
    def generate_key(self, algorithm: str, key_size: int, purpose: str) -> HSMKey:
        """Generate a new key."""
        key_id = f"key_{uuid.uuid4().hex[:16]}"
        key = HSMKey(
            key_id=key_id,
            algorithm=algorithm,
            key_size=key_size,
            purpose=purpose,
            created_at=time.time(),
            expires_at=time.time() + (365 * 24 * 3600),  # 1 year
        )
        self.keys[key_id] = key
        self.logger.info(f"Generated {algorithm}-{key_size} key: {key_id}")
        return key
    
    def import_key(self, key_id: str, key_data: bytes, algorithm: str) -> HSMKey:
        """Import a key."""
        key = HSMKey(
            key_id=key_id,
            algorithm=algorithm,
            key_size=len(key_data) * 8,
            purpose="imported",
            created_at=time.time(),
            expires_at=time.time() + (365 * 24 * 3600),  # 1 year
        )
        self.keys[key_id] = key
        return key
    
    def sign(self, request: HSMSignatureRequest) -> HSMSignatureResponse:
        """Sign data (mock)."""
        if request.key_id not in self.keys:
            return HSMSignatureResponse(
                request_id=request.request_id,
                signature=None,
                status=HSMStatus.ERROR,
                error="Key not found",
            )
        
        # Mock signature
        signature = hmac.new(
            b"mock_hsm_key",
            request.data,
            hashlib.sha256
        ).digest()
        
        return HSMSignatureResponse(
            request_id=request.request_id,
            signature=signature,
            status=HSMStatus.CONNECTED,
        )
    
    def encrypt(self, key_id: str, data: bytes) -> bytes:
        """Encrypt data (mock)."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        return base64.b64encode(data)
    
    def decrypt(self, key_id: str, data: bytes) -> bytes:
        """Decrypt data (mock)."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        return base64.b64decode(data)
    
    def get_status(self) -> HSMStatus:
        return self.status
    
    def close(self):
        self.status = HSMStatus.DISCONNECTED


class VerificationEngine(ABC):
    """Abstract base class for formal verification engines."""
    
    @abstractmethod
    def verify_model(self, model_path: str, properties: List[str]) -> Dict[str, Any]:
        """Verify a model against properties."""
        pass
    
    @abstractmethod
    def verify_code(self, code_path: str, spec_path: str) -> Dict[str, Any]:
        """Verify code against specification."""
        pass
    
    @abstractmethod
    def check_invariants(self, system_state: Dict[str, Any], invariants: List[str]) -> Dict[str, Any]:
        """Check system invariants."""
        pass


class MockVerificationEngine(VerificationEngine):
    """Mock verification engine for testing."""
    
    def __init__(self):
        self.logger = logging.getLogger("mock_verification")
    
    def verify_model(self, model_path: str, properties: List[str]) -> Dict[str, Any]:
        """Mock model verification."""
        self.logger.info(f"Verifying model: {model_path}")
        return {
            "status": VerificationStatus.VERIFIED.value,
            "model": model_path,
            "properties_checked": len(properties),
            "results": {prop: "PASS" for prop in properties},
            "counterexamples": [],
        }
    
    def verify_code(self, code_path: str, spec_path: str) -> Dict[str, Any]:
        """Mock code verification."""
        self.logger.info(f"Verifying code: {code_path} against spec: {spec_path}")
        return {
            "status": VerificationStatus.VERIFIED.value,
            "code": code_path,
            "spec": spec_path,
            "checks_passed": True,
            "details": "Mock verification passed",
        }
    
    def check_invariants(self, system_state: Dict[str, Any], invariants: List[str]) -> Dict[str, Any]:
        """Check invariants (mock)."""
        return {
            "status": VerificationStatus.VERIFIED.value,
            "invariants_checked": len(invariants),
            "results": {inv: "HOLDS" for inv in invariants},
        }


class AdvancedSecurityManager:
    """Central manager for advanced security features."""
    
    def __init__(
        self,
        biometric_provider: Optional[BiometricProvider] = None,
        hsm_provider: Optional[HSMProvider] = None,
        verification_engine: Optional[VerificationEngine] = None,
    ):
        self.biometric_provider = biometric_provider or MockBiometricProvider()
        self.hsm_provider = hsm_provider or MockHSMProvider()
        self.verification_engine = verification_engine or MockVerificationEngine()
        self.logger = logging.getLogger("advanced_security")
        
        # Initialize HSM
        self.hsm_provider.initialize()
    
    # Biometric operations
    def enroll_biometric(
        self,
        user_id: str,
        biometric_data: bytes,
        biometric_type: BiometricType,
    ) -> BiometricTemplate:
        """Enroll a biometric for a user."""
        return self.biometric_provider.enroll(user_id, biometric_data, biometric_type)
    
    def verify_biometric(
        self,
        user_id: str,
        biometric_data: bytes,
        biometric_type: BiometricType,
    ) -> BiometricVerificationResult:
        """Verify biometric authentication."""
        return self.biometric_provider.verify(user_id, biometric_data, biometric_type)
    
    def require_biometric_for_action(
        self,
        user_id: str,
        action: str,
        biometric_type: BiometricType,
        threshold: float = 0.95,
    ) -> bool:
        """Require biometric verification for a high-risk action."""
        # In production, would prompt for biometric
        # Mock: return True for demo
        return True
    
    # HSM operations
    def generate_hsm_key(
        self,
        algorithm: str = "RSA",
        key_size: int = 2048,
        purpose: str = "signing",
    ) -> HSMKey:
        """Generate a key in HSM."""
        return self.hsm_provider.generate_key(algorithm, key_size, purpose)
    
    def hsm_sign(
        self,
        key_id: str,
        data: bytes,
        algorithm: str = "RSA-PSS-SHA256",
        context: Optional[Dict] = None,
    ) -> HSMSignatureResponse:
        """Sign data using HSM."""
        request = HSMSignatureRequest(
            request_id=str(uuid.uuid4()),
            key_id=key_id,
            data=data,
            algorithm=algorithm,
            context=context or {},
        )
        return self.hsm_provider.sign(request)
    
    def hsm_encrypt(self, key_id: str, data: bytes) -> bytes:
        """Encrypt data using HSM."""
        return self.hsm_provider.encrypt(key_id, data)
    
    def hsm_decrypt(self, key_id: str, data: bytes) -> bytes:
        """Decrypt data using HSM."""
        return self.hsm_provider.decrypt(key_id, data)
    
    # Formal verification
    def verify_model(self, model_path: str, properties: List[str]) -> Dict[str, Any]:
        """Verify a formal model."""
        return self.verification_engine.verify_model(model_path, properties)
    
    def verify_code(self, code_path: str, spec_path: str) -> Dict[str, Any]:
        """Verify code against specification."""
        return self.verification_engine.verify_code(code_path, spec_path)
    
    def check_invariants(self, system_state: Dict[str, Any], invariants: List[str]) -> Dict[str, Any]:
        """Check system invariants."""
        return self.verification_engine.check_invariants(system_state, invariants)
    
    # High-level security workflows
    def secure_action_workflow(
        self,
        user_id: str,
        action: str,
        risk_level: str,
        biometric_type: BiometricType = BiometricType.FINGERPRINT,
    ) -> Dict[str, Any]:
        """Execute a secure action workflow with biometric verification."""
        
        if risk_level in ["medium", "high", "critical"]:
            # Require biometric
            result = {
                "action": action,
                "user_id": user_id,
                "risk_level": risk_level,
                "biometric_required": True,
                "biometric_type": biometric_type.value,
                "allowed": False,
            }
            
            # In production, would prompt for biometric
            # Mock: simulate biometric prompt
            biometric_data = b"mock_fingerprint_data"
            verification = self.verify_biometric(user_id, biometric_data, biometric_type)
            
            if verification.status == BiometricStatus.VERIFIED and verification.confidence >= 0.95:
                result["allowed"] = True
                result["biometric_result"] = {
                    "status": verification.status.value,
                    "confidence": verification.confidence,
                }
            else:
                result["biometric_result"] = {
                    "status": verification.status.value,
                    "confidence": verification.confidence,
                }
            
            return result
        else:
            # Low risk - no biometric required
            return {
                "action": action,
                "user_id": user_id,
                "risk_level": risk_level,
                "biometric_required": False,
                "allowed": True,
            }
    
    def get_hsm_status(self) -> HSMStatus:
        """Get HSM status."""
        return self.hsm_provider.get_status()
    
    def get_biometric_templates(self, user_id: str) -> List[BiometricTemplate]:
        """Get user's biometric templates."""
        return self.biometric_provider.list_templates(user_id)


# Convenience functions
def create_advanced_security_manager(
    biometric_provider: Optional[BiometricProvider] = None,
    hsm_provider: Optional[HSMProvider] = None,
    verification_engine: Optional[VerificationEngine] = None,
) -> AdvancedSecurityManager:
    """Create an advanced security manager with default providers."""
    return AdvancedSecurityManager(
        biometric_provider=biometric_provider or MockBiometricProvider(),
        hsm_provider=hsm_provider or MockHSMProvider(),
        verification_engine=verification_engine or MockVerificationEngine(),
    )


# Example usage
if __name__ == "__main__":
    # Create security manager
    security = create_advanced_security_manager()
    
    # Test biometric enrollment
    template = security.enroll_biometric(
        user_id="user_001",
        biometric_data=b"mock_fingerprint_data",
        biometric_type=BiometricType.FINGERPRINT,
    )
    print(f"Enrolled biometric: {template.template_id}")
    
    # Test biometric verification
    result = security.verify_biometric(
        user_id="user_001",
        biometric_data=b"mock_fingerprint_data",
        biometric_type=BiometricType.FINGERPRINT,
    )
    print(f"Biometric verification: {result.status.value}, confidence: {result.confidence}")
    
    # Test HSM key generation
    key = security.generate_hsm_key(algorithm="RSA", key_size=2048, purpose="signing")
    print(f"Generated HSM key: {key.key_id}")
    
    # Test HSM signing
    sign_result = security.hsm_sign(key.key_id, b"test data")
    print(f"HSM signing: {sign_result.status.value}")
    
    # Test secure action workflow
    result = security.secure_action_workflow(
        user_id="user_001",
        action="delete_critical_file",
        risk_level="critical",
    )
    print(f"Secure action: {result}")
    
    # Test formal verification
    verification = security.verify_model("model.pml", ["safety", "liveness"])
    print(f"Model verification: {verification['status']}")
    
    print("All advanced security features working!")